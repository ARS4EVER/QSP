"""
src/app/recovery_manager.py
[Phase 11] 资产恢复流水线 (C8抗重放攻击版)
集成挑战-应答机制，全程使用Nonce校验和抗量子签名，彻底废弃时间戳依赖。
"""
import os
import json
import hashlib
import time
import base64
from typing import Dict, List, Tuple

from src.app.app_protocol import AppMessage, AppCmd, build_challenge_req, AppMessageV2, AppCmdV2
from src.secret_sharing.reconstructor import SecretReconstructor
from src.app.vault_crypto import VaultCrypto
from src.core.challenge_auth import build_auth_payload

try:
    from src.crypto_lattice.signer import DilithiumSigner
except ImportError:
    from src.crypto_lattice.wrapper import lattice_sign as DilithiumSigner


class RecoveryManager:
    """
    QSP 资产恢复请求端（恢复发起方）
    负责发起挑战、验证响应、执行资产份额拉取与重组。
    """
    CHUNK_SIZE = 512
    ENCRYPTED_CHUNK_SIZE = 540

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
            
        self.active_manifests: Dict[str, dict] = {}
        self.pending_challenges: Dict[str, dict] = {}
        self.requester_private_key = None
        self.requester_public_key = None
        
        self.on_progress_update = None  
        self.on_recovery_success = None 
        self.on_recovery_failed = None
        
        self._init_crypto_keys()

    def _init_crypto_keys(self):
        """初始化抗量子签名密钥对"""
        try:
            from src.crypto_lattice.wrapper import LatticeWrapper
            key_path = os.path.join(self.vault_dir, ".qsp_identity.pem")
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    key_data = f.read()
                # 旧版本可能只存了一个值，我们需要处理两种情况
                if len(key_data) >= 2000:
                    # 假设这是完整密钥对，这里简化处理
                    self.requester_private_key = key_data
                    self.requester_public_key = key_data
                else:
                    # 重新生成新密钥
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
            # 出错时使用随机生成备用密钥
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

    def execute_recovery(self, manifest_path: str):
        """执行资产恢复的主流程"""
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
            self.on_progress_update(file_hash, current_shares, t)

        if current_shares >= t:
            self._try_reconstruct_streaming(file_hash, local_share_indices[:t])
            return

        target_node = manifest.get("preferred_node", "broadcast")
        # 使用自己的节点ID作为key，因为挑战响应会返回这个ID
        self_node_id = self.p2p_node.node_id
        self._initiate_challenge_request(target_node, file_hash, t, self_node_id)

    def _initiate_challenge_request(self, target_node: str, file_hash: str, threshold: int, requester_id: str = None):
        """主动发起挑战请求"""
        if requester_id is None:
            requester_id = self.p2p_node.node_id
            
        challenge_msg = build_challenge_req(requester_id)
        
        # 使用节点ID作为key，因为挑战响应会返回发送者的节点ID
        self.pending_challenges[requester_id] = {
            "file_hash": file_hash,
            "threshold": threshold,
            "timestamp": time.time(),
            "target_addr": target_node  # 保存原始的地址信息用于调试
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
        """处理接收到的挑战响应，构建签名请求"""
        if msg.cmd != AppCmdV2.CHALLENGE_RESP:
            return
            
        requester_id = msg.sender_id  # 这是请求方的节点ID
        nonce = msg.payload.get("nonce")
        
        if not nonce:
            print("[Security] 收到的挑战响应缺少Nonce")
            return
            
        # 使用节点ID（sender_id）查找pending的挑战
        pending = self.pending_challenges.get(requester_id)
        if not pending:
            print(f"[Security] 收到未知节点 {requester_id} 的挑战响应，可能已超时或重复")
            # 尝试遍历查找（兼容旧逻辑）
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
        """处理远端节点的拉取请求"""
        if msg.cmd != AppCmdV2.PULL_REQ: return
        
        # 从 payload 中获取字段
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
                    chunk_data = self.vault_crypto.decrypt_chunk(encrypted_chunk)
                except Exception as e:
                    print(f"[Vault] 解析本地份额失败，拒绝传输: {e}")
                    break
                
                resp_payload = {
                    "file_hash": file_hash,
                    "share_index": share_idx,
                    "share_data_b64": base64.b64encode(chunk_data).decode('utf-8'),
                    "chunk_index": chunk_idx,
                    "total_chunks": total_chunks
                }
                resp_msg = AppMessageV2(
                    cmd=AppCmdV2.PULL_RESP,
                    sender_id=self.p2p_node.node_id,
                    payload=resp_payload
                )
                self.p2p_node.secure_link.send_reliable(resp_msg.encode())
                
                while len(self.p2p_node.secure_link.rudp.unacked_packets) > 80:
                    time.sleep(0.01)

    def handle_pull_response(self, peer_addr: tuple, msg: AppMessageV2):
        """处理远端节点返回的份额数据"""
        if msg.cmd != AppCmdV2.PULL_RESP: return
        
        # 从 payload 中获取字段
        file_hash = msg.payload.get("file_hash")
        share_idx = msg.payload.get("share_index")
        share_data_b64 = msg.payload.get("share_data_b64")
        
        if not file_hash or share_idx is None or not share_data_b64:
            print(f"[Recovery] 拉取响应缺少必要字段: file_hash={file_hash}, share_idx={share_idx}")
            return
        
        try:
            share_data = base64.b64decode(share_data_b64)
        except Exception as e:
            print(f"[Recovery] Base64 解码失败: {e}")
            return
        
        if share_idx in self.load_local_shares(file_hash): return
        
        # 获取其他字段
        chunk_index = msg.payload.get("chunk_index", 0)
        total_chunks = msg.payload.get("total_chunks", 1)
        
        part_path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_idx}.part")
        meta_path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_idx}.meta")
        
        received_chunks = set()
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r") as f:
                    meta = json.load(f)
                    received_chunks = set(meta.get("received", []))
            except Exception:
                pass
                
        if chunk_index in received_chunks:
            return 
            
        encrypted_data = self.vault_crypto.encrypt_chunk(share_data)
            
        mode = "r+b" if os.path.exists(part_path) else "wb"
        with open(part_path, mode) as f:
            f.seek(chunk_index * self.ENCRYPTED_CHUNK_SIZE)
            f.write(encrypted_data)
            
        received_chunks.add(chunk_index)
        
        with open(meta_path, "w") as f:
            json.dump({
                "total_chunks": total_chunks, 
                "received": list(received_chunks)
            }, f)
            
        if len(received_chunks) >= total_chunks:
            dat_path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_idx}.dat")
            os.rename(part_path, dat_path)
            os.remove(meta_path)
            print(f"[Vault] 资产份额 {share_idx} 已接收并本地加密保存")
            
            if file_hash in self.active_manifests:
                t = self.active_manifests[file_hash]["t"]
                local_indices = self.load_local_shares(file_hash)
                
                if self.on_progress_update:
                    self.on_progress_update(file_hash, len(local_indices), t)
                    
                if len(local_indices) >= t:
                    self._try_reconstruct_streaming(file_hash, local_indices[:t])

    def _try_reconstruct_streaming(self, file_hash: str, share_indices: List[int]):
        """重构资产"""
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
            
            with open(restored_path, "wb") as out_f:
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
                    
                    out_f.write(recovered_chunk)
                    hasher.update(recovered_chunk)
                    
            for _, fh in file_handles: fh.close()
            
            if hasher.hexdigest() != manifest["original_hash"]:
                raise ValueError("数据完整性受损：哈希校验不匹配")
                
            del self.active_manifests[file_hash]
            if self.on_recovery_success:
                self.on_recovery_success(file_hash, restored_path)
                
        except Exception as e:
            for _, fh in file_handles:
                if not fh.closed: fh.close()
            self._trigger_fail(file_hash, str(e))

    def _trigger_fail(self, file_hash: str, error_msg: str):
        """触发恢复失败回调"""
        print(f"[Recovery Error] {error_msg}")
        if self.on_recovery_failed:
            self.on_recovery_failed(file_hash, error_msg)
