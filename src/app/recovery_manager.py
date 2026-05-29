"""
src/app/recovery_manager.py
[Phase 11] 资产恢复流水线 (C8抗重放攻击版)
集成挑战-应答机制，全程使用Nonce校验和抗量子签名

[Performance Optimization] 双层切片架构支持
"""
import os
import json
import hashlib
import time
import base64
from typing import Dict, List, Tuple, Optional, Callable

from src.app.app_protocol import AppMessage, AppCmd, build_challenge_req, AppMessageV2, AppCmdV2
from src.secret_sharing.reconstructor import SecretReconstructor
from src.app.vault_crypto import VaultCrypto
from src.core.challenge_auth import build_auth_payload

try:
    from src.crypto_lattice.signer import DilithiumSigner
except ImportError:
    from src.crypto_lattice.wrapper import lattice_sign as DilithiumSigner


class RecoveryManager:
    # 【双层切片常量】与BackupManager保持一致
    BLOCK_SIZE = 1024 * 1024  # 1MB：应用层文件读取与混合密码学处理的单位
    FRAGMENT_SIZE = 1024      # 1KB：网络层 UDP 发送的安全载荷单位
    ENCRYPTED_CHUNK_SIZE = 0  # 动态计算

    def __init__(self, p2p_node, vault_crypto=None, vault_dir: str = "./vault", vault_password: str = None):
        self.p2p_node = p2p_node
        self.vault_dir = vault_dir
        
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)
            
        if vault_crypto is not None:
            self.vault_crypto = vault_crypto
        elif vault_password is not None:
            self.vault_crypto = VaultCrypto(vault_password, vault_dir=vault_dir)
        else:
            raise ValueError("必须提供 vault_crypto 或 vault_password 参数")
            
        # 【新增】网络碎片重组缓冲池
        self.frag_buffers = {}
        
        self.active_manifests: Dict[str, dict] = {}
        self.pending_challenges: Dict[str, dict] = {}
        self.requester_private_key = None
        self.requester_public_key = None
        
        self.on_progress_update: Optional[Callable] = None  
        self.on_recovery_success = None 
        self.on_recovery_failed = None
        
        self._init_crypto_keys()
        self._compute_encrypted_chunk_size()

    def _compute_encrypted_chunk_size(self):
        """动态计算本地金库落盘的加密块大小"""
        dummy_data = b'\0' * self.BLOCK_SIZE
        dummy_encrypted = self.vault_crypto.encrypt_chunk(dummy_data)
        self.ENCRYPTED_CHUNK_SIZE = len(dummy_encrypted)

    def _init_crypto_keys(self):
        try:
            from src.crypto_lattice.wrapper import LatticeWrapper
            key_path = os.path.join(self.vault_dir, ".qsp_identity.pem")
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    key_data = f.read()
                if len(key_data) >= 2000:
                    self.requester_private_key = key_data
                    self.requester_public_key = key_data
                else:
                    pk, sk = LatticeWrapper.generate_signing_keypair()
                    self.requester_private_key = sk
                    self.requester_public_key = pk
                    with open(key_path, "wb") as f:
                        f.write(sk)
            else:
                pk, sk = LatticeWrapper.generate_signing_keypair()
                self.requester_private_key = sk
                self.requester_public_key = pk
                with open(key_path, "wb") as f:
                    f.write(sk)
        except Exception as e:
            print(f"[Recovery] 抗量子密钥初始化失败: {e}")
            self.requester_private_key = os.urandom(2420)[:2420]
            self.requester_public_key = self.requester_private_key

    def load_local_shares(self, file_hash: str) -> List[int]:
        share_indices = []
        if not os.path.exists(self.vault_dir): 
            return share_indices
            
        for filename in os.listdir(self.vault_dir):
            if filename.startswith(file_hash) and filename.endswith(".dat") and "_share_" in filename:
                try:
                    idx = int(filename.split("_share_")[1].split(".dat")[0])
                    share_indices.append(idx)
                except Exception:
                    continue
        return share_indices

    def _update_progress(self, file_hash: str, processed: int, total: int):
        """更新进度并调用回调函数"""
        if self.on_progress_update:
            manifest = self.active_manifests.get(file_hash)
            if manifest:
                t = manifest.get("t", 1)
                progress = (processed / total) * 100
                self.on_progress_update(file_hash, processed, total, progress, "计算中...")

    def execute_recovery(self, manifest_path: str):
        if not os.path.exists(manifest_path):
            raise FileNotFoundError("Manifest 清单文件不存在！")
            
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
            
        file_hash = manifest["original_hash"]
        t = manifest["t"]
        self.active_manifests[file_hash] = manifest
        
        local_share_indices = self.load_local_shares(file_hash)
        current_shares = len(local_share_indices)
        
        if self.on_progress_update:
            self.on_progress_update(file_hash, current_shares, t, current_shares / t * 100, "准备中...")

        if current_shares >= t:
            self._try_reconstruct_streaming(file_hash, local_share_indices[:t])
            return

        target_node = manifest.get("preferred_node", "broadcast")
        self_node_id = self.p2p_node.node_id
        self._initiate_challenge_request(target_node, file_hash, t, self_node_id)

    def _initiate_challenge_request(self, target_node: str, file_hash: str, threshold: int, requester_id: str = None):
        if requester_id is None:
            requester_id = self.p2p_node.node_id
            
        challenge_msg = build_challenge_req(requester_id)
        
        self.pending_challenges[requester_id] = {
            "file_hash": file_hash,
            "threshold": threshold,
            "timestamp": time.time(),
            "target_addr": target_node 
        }
        
        if getattr(self.p2p_node, 'secure_link', None):
            try:
                encoded = challenge_msg.encode()
                self.p2p_node.secure_link.send_reliable(encoded)
                print(f"[Recovery] 正在发起挑战请求以恢复 {file_hash}...")
            except Exception as e:
                self._trigger_fail(file_hash, f"挑战请求发送失败: {e}")
        else:
            self._trigger_fail(file_hash, "无法建立P2P连接")

    def handle_challenge_response(self, peer_addr: tuple, msg: AppMessageV2):
        if msg.cmd != AppCmdV2.CHALLENGE_RESP:
            return
            
        requester_id = msg.sender_id
        nonce = msg.payload.get("nonce")
        
        if not nonce:
            print("[Security] 收到的挑战响应缺少Nonce")
            return
            
        pending = self.pending_challenges.get(requester_id)
        if not pending:
            print(f"[Security] 收到未知节点 {requester_id} 的挑战响应")
            for key, value in list(self.pending_challenges.items()):
                if abs(time.time() - value.get("timestamp", 0)) < 300:
                    pending = value
                    requester_id = key
                    break
            if not pending:
                return
            
        file_hash = pending["file_hash"]
        threshold = pending["threshold"]
        
        try:
            expected_payload = build_auth_payload(file_hash, threshold, nonce)
            signature = DilithiumSigner.sign(self.requester_private_key, expected_payload)
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            public_key_b64 = base64.b64encode(self.requester_public_key).decode('utf-8')
            
            pull_req_payload = {
                "file_hash": file_hash,
                "threshold": threshold,
                "nonce": nonce,
                "signature": signature_b64,
                "public_key": public_key_b64,
                "requester_id": self.p2p_node.node_id
            }
            
            pull_msg = AppMessageV2(
                cmd=AppCmdV2.PULL_REQ,
                sender_id=self.p2p_node.node_id,
                payload=pull_req_payload
            )
            
            if getattr(self.p2p_node, 'secure_link', None):
                encoded = pull_msg.encode()
                self.p2p_node.secure_link.send_reliable(encoded)
                print(f"[Recovery] 已发送带签名的拉取请求 (阈值: {threshold})")
                
        except Exception as e:
            self._trigger_fail(file_hash, f"签名构建失败: {e}")

    def handle_pull_request(self, peer_addr: tuple, msg: AppMessageV2):
        """处理拉取请求（双层切片发送端：大块读取，碎步发送）"""
        if msg.cmd != AppCmdV2.PULL_REQ: return
        
        file_hash = msg.payload.get("file_hash")
        if not file_hash:
            print("[Recovery] 拉取请求缺少 file_hash")
            return
            
        local_shares = self.load_local_shares(file_hash)
        
        if not local_shares or not getattr(self.p2p_node, 'secure_link', None):
                error_payload = {"file_hash": file_hash, "error_msg": "未找到份额"}
                error_msg = AppMessageV2(cmd=AppCmdV2.PULL_REJECT, sender_id=self.p2p_node.node_id, payload=error_payload)
                self.p2p_node.secure_link.send_reliable(error_msg.encode())
                return
                
        share_idx = local_shares[0]
        path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_idx}.dat")
        file_size = os.path.getsize(path)
        total_chunks = max(1, (file_size + self.ENCRYPTED_CHUNK_SIZE - 1) // self.ENCRYPTED_CHUNK_SIZE)
        
        with open(path, "rb") as f:
            for chunk_idx in range(total_chunks):
                encrypted_chunk = f.read(self.ENCRYPTED_CHUNK_SIZE)
                if not encrypted_chunk: break
                
                try:
                    # 解密得到1MB的原始份额数据
                    chunk_data = self.vault_crypto.decrypt_chunk(encrypted_chunk)
                except Exception as e:
                    print(f"[Vault] 解析本地份额失败，拒绝传输: {e}")
                    break
                
                # 计算当前1MB份额需要被切割成多少个1KB的网络碎片
                total_frags = (len(chunk_data) + self.FRAGMENT_SIZE - 1) // self.FRAGMENT_SIZE
                
                for frag_idx in range(total_frags):
                    # 提取1KB碎片载荷
                    start_pos = frag_idx * self.FRAGMENT_SIZE
                    end_pos = start_pos + self.FRAGMENT_SIZE
                    frag_data = chunk_data[start_pos:end_pos]
                    
                    # 构建包含碎片定界信息的元数据
                    resp_payload = {
                        "file_hash": file_hash,
                        "share_index": share_idx,
                        "chunk_index": chunk_idx,
                        "total_chunks": total_chunks,
                        "frag_index": frag_idx,
                        "total_frags": total_frags
                    }
                    resp_msg = AppMessageV2(
                        cmd=AppCmdV2.PULL_RESP,
                        sender_id=self.p2p_node.node_id,
                        payload=resp_payload,
                        raw_payload=frag_data
                    )
                    self.p2p_node.secure_link.send_reliable(resp_msg.encode())
                    
                    # 事件驱动流控
                    secure_link = self.p2p_node.secure_link
                    cc = getattr(secure_link, 'cc', None) or getattr(secure_link, 'congestion_control', None)
                    cwnd_packets = max(10, cc.get_cwnd_packets()) if cc else 100
                    secure_link.rudp.wait_for_window(cwnd_packets)

    def handle_pull_response(self, peer_addr: tuple, msg: AppMessageV2):
        """处理拉取响应（双层切片接收端：碎片内存拼装，单次大块落盘）"""
        if msg.cmd != AppCmdV2.PULL_RESP: return

        file_hash = msg.payload.get("file_hash")
        share_idx = msg.payload.get("share_index")
        
        # 优先从raw_payload获取数据
        share_data_frag = msg.raw_payload
        
        # 兼容旧格式
        if not share_data_frag and "share_data_b64" in msg.payload:
            try:
                share_data_frag = base64.b64decode(msg.payload["share_data_b64"])
            except Exception as e:
                print(f"[Recovery] Base64 解码失败: {e}")
                return
        elif not share_data_frag and "share_data" in msg.payload:
            share_data_frag = msg.payload["share_data"]
        
        if not file_hash or share_idx is None or not share_data_frag:
            print(f"[Recovery] 拉取响应缺少必要字段: file_hash={file_hash}, share_idx={share_idx}")
            return
        
        # 获取碎片信息
        chunk_index = msg.payload.get("chunk_index", 0)
        total_chunks = msg.payload.get("total_chunks", 1)
        frag_index = msg.payload.get("frag_index", 0)
        total_frags = msg.payload.get("total_frags", 1)
        
        # 构建该1MB大块的唯一缓冲键名
        buf_key = f"{file_hash}_{share_idx}_{chunk_index}"
        
        # 初始化缓冲池
        if buf_key not in self.frag_buffers:
            self.frag_buffers[buf_key] = {
                "frags": {},
                "received": 0,
                "total": total_frags
            }
            
        buf = self.frag_buffers[buf_key]
        
        # 记录到达的碎片
        if frag_index not in buf["frags"]:
            buf["frags"][frag_index] = share_data_frag
            buf["received"] += 1
            
        # 【核心屏障】当该1MB大块的所有碎片收集完毕时，触发合并与落盘
        if buf["received"] == buf["total"]:
            # 按索引严格按序拼装成1MB原始加密份额
            full_share_data = b"".join(buf["frags"][i] for i in range(buf["total"]))
            
            # 释放内存
            del self.frag_buffers[buf_key]
            
            # 仅对完整的1MB块进行一次本地金库加密
            encrypted_data = self.vault_crypto.encrypt_chunk(full_share_data)
            
            part_path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_idx}.part")
            meta_path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_idx}.meta")
            
            # 读取已接收的块索引
            received_chunks = set()
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                        received_chunks = set(meta.get("received", []))
                except Exception:
                    pass
            
            received_chunks.add(chunk_index)
            
            # 写入加密数据
            mode = "r+b" if os.path.exists(part_path) else "wb"
            with open(part_path, mode) as f:
                f.seek(chunk_index * self.ENCRYPTED_CHUNK_SIZE)
                f.write(encrypted_data)
            
            # 保存元数据
            with open(meta_path, "w") as f:
                json.dump({
                    "total_chunks": total_chunks,
                    "received": list(received_chunks)
                }, f)
            
            # 更新进度
            if self.on_progress_update and file_hash in self.active_manifests:
                manifest = self.active_manifests[file_hash]
                t = manifest["t"]
                local_indices = self.load_local_shares(file_hash)
                progress = (len(received_chunks) / total_chunks) * 100 if total_chunks > 0 else 0
                self.on_progress_update(file_hash, len(local_indices), t, progress, "计算中...")
            
            # 检查是否所有块都已接收
            if len(received_chunks) >= total_chunks:
                dat_path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_idx}.dat")
                
                # 如果目标文件已存在，先删除它
                if os.path.exists(dat_path):
                    try:
                        os.remove(dat_path)
                        print(f"[Vault] 已清理旧的份额文件: {os.path.basename(dat_path)}")
                    except Exception as e:
                        print(f"[Vault] 警告：无法删除旧份额文件: {e}")
                
                # 执行重命名
                os.rename(part_path, dat_path)
                
                # 删除元数据文件
                try:
                    os.remove(meta_path)
                except Exception as e:
                    print(f"[Vault] 警告：无法删除元数据文件: {e}")
                
                print(f"[Vault] 资产份额 {share_idx} 已接收并本地加密保存")
                
                if file_hash in self.active_manifests:
                    t = self.active_manifests[file_hash]["t"]
                    local_indices = self.load_local_shares(file_hash)
                    
                    if self.on_progress_update:
                        self.on_progress_update(file_hash, len(local_indices), t, len(local_indices)/t*100, "准备中...")
                        
                    if len(local_indices) >= t:
                        self._try_reconstruct_streaming(file_hash, local_indices[:t])

    def _try_reconstruct_streaming(self, file_hash: str, share_indices: List[int]):
        manifest = self.active_manifests.get(file_hash)
        if not manifest: return
        t = manifest["t"]
        
        restored_filename = f"recovered_{manifest['filename']}"
        output_dir = "./data/restored"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        restored_path = os.path.join(output_dir, restored_filename)
        
        file_handles = []
        try:
            for idx in share_indices[:t]:
                path = os.path.join(self.vault_dir, f"{file_hash}_share_{idx}.dat")
                file_handles.append((idx, open(path, "rb")))
                
            hasher = hashlib.sha256()
            total_size = manifest.get("file_size", 0)
            processed_size = 0
            original_size = manifest.get("file_size", 0)
            
            print(f"\n[RecoveryManager] ========== 开始哈希校验 ==========")
            print(f"[RecoveryManager] 原始文件大小: {original_size} bytes")
            print(f"[RecoveryManager] 原始哈希值: {manifest.get('original_hash', 'N/A')[:16]}...")
            
            with open(restored_path, "wb") as out_f:
                chunk_count = 0
                while True:
                    chunk_shares = []
                    for idx, fh in file_handles:
                        encrypted_chunk = fh.read(self.ENCRYPTED_CHUNK_SIZE)
                        if encrypted_chunk:
                            try:
                                chunk = self.vault_crypto.decrypt_chunk(encrypted_chunk)
                                chunk_shares.append((idx, chunk))
                            except Exception as e:
                                raise ValueError(f"金库数据解密失败: {e}")
                                
                    if len(chunk_shares) < t or len(chunk_shares[0][1]) == 0:
                        break 
                        
                    recovered_chunk = SecretReconstructor.reconstruct(chunk_shares)
                    
                    # 计算本块中实际有效的数据长度（不包含末尾补零）
                    bytes_remaining = original_size - processed_size
                    actual_data_length = min(len(recovered_chunk), bytes_remaining)
                    
                    out_f.write(recovered_chunk)
                    
                    # 只对实际数据计算哈希（不包括补零）
                    hasher.update(recovered_chunk[:actual_data_length])
                    
                    if chunk_count < 3 or chunk_count % 100 == 0:
                        print(f"[RecoveryManager] 处理块 {chunk_count}: 重构长度={len(recovered_chunk)}, 有效长度={actual_data_length}")
                    chunk_count += 1
                    
                    processed_size += len(recovered_chunk)
                    if self.on_progress_update:
                        progress = min(min(processed_size, original_size) / original_size * 100, 100) if original_size > 0 else 0
                        self.on_progress_update(file_hash, len(share_indices), t, progress, "恢复中...")
                
            for _, fh in file_handles: fh.close()
            
            # 根据原始大小裁剪文件（处理补零问题）
            if os.path.exists(restored_path):
                with open(restored_path, "r+b") as f:
                    if original_size is not None:
                        f.truncate(original_size)
                        print(f"[RecoveryManager] 文件已裁剪到原始大小: {original_size} bytes")
            
            # 最终哈希校验
            calculated_hash = hasher.hexdigest()
            expected_hash = manifest["original_hash"]
            
            print(f"[RecoveryManager] 计算哈希值: {calculated_hash[:16]}...")
            print(f"[RecoveryManager] 期望哈希值: {expected_hash[:16]}...")
            
            if calculated_hash != expected_hash:
                print(f"[RecoveryManager] ======================================")
                print(f"[RecoveryManager] ❌ 哈希校验不匹配！")
                print(f"[RecoveryManager] 可能原因:")
                print(f"[RecoveryManager]   1. 份额数据损坏或不完整")
                print(f"[RecoveryManager]   2. 恢复时使用的份额数量不足")
                print(f"[RecoveryManager]   3. 补零处理逻辑有问题")
                print(f"[RecoveryManager] ======================================")
                
                # 额外调试：重新计算一次文件哈希，看看问题所在
                print(f"\n[RecoveryManager] ========== 额外验证 ==========")
                file_checker = hashlib.sha256()
                try:
                    with open(restored_path, "rb") as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            file_checker.update(chunk)
                    print(f"[RecoveryManager] 从文件直接计算的哈希: {file_checker.hexdigest()[:16]}...")
                except Exception as e:
                    print(f"[RecoveryManager] 额外验证失败: {e}")
                print(f"[RecoveryManager] =============================\n")
                
                raise ValueError("数据完整性受损：哈希校验不匹配")
            
            print(f"[RecoveryManager] ✓ 哈希校验通过！")
            print(f"[RecoveryManager] =====================================\n")
                
            del self.active_manifests[file_hash]
            if self.on_recovery_success:
                self.on_recovery_success(file_hash, restored_path)
                
        except Exception as e:
            for _, fh in file_handles:
                if not fh.closed: fh.close()
            self._trigger_fail(file_hash, str(e))

    def _trigger_fail(self, file_hash: str, error_msg: str):
        print(f"[Recovery Error] {error_msg}")
        if self.on_recovery_failed:
            self.on_recovery_failed(file_hash, error_msg)
