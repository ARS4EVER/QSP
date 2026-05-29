import os
import json
import hashlib
import time
from typing import Optional, Callable, Dict, Set

import base64
from src.app.app_protocol import AppMessage, AppCmd, AppMessageV2, AppCmdV2
from src.secret_sharing.splitter import SecretSplitter
from src.app.vault_crypto import VaultCrypto
from src.app.manifest_key_manager import ManifestKeyManager

class BackupManager:
    # 【双层切片常量】
    BLOCK_SIZE = 1024 * 1024  # 1MB：应用层文件读取与混合密码学处理的单位
    FRAGMENT_SIZE = 1024      # 1KB：网络层 UDP 发送的安全载荷单位 (留足空间给 Header)

    def __init__(self, p2p_node, vault_crypto, vault_dir: str = "./data/shares"):
        self.p2p_node = p2p_node
        self.vault_dir = vault_dir
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)
            
        self.vault_crypto = vault_crypto
        self.manifest_key_manager = None
        
        # 进度回调函数
        self.on_progress_update: Optional[Callable[[str, int, int, float, str], None]] = None
        
        # 【新增】网络碎片重组缓冲池
        self.frag_buffers = {}
        
        # 初始化清单密钥管理器
        self._init_manifest_key_manager()
        
        # 动态计算本地金库落盘的加密块大小
        self._compute_encrypted_chunk_size()

    def _init_manifest_key_manager(self):
        """初始化清单密钥管理器"""
        if hasattr(self.vault_crypto, 'password'):
            password = self.vault_crypto.password.decode('utf-8') if isinstance(self.vault_crypto.password, bytes) else self.vault_crypto.password
            self.manifest_key_manager = ManifestKeyManager(password)
            print(f"[BackupManager] ✓ 清单密钥管理器已初始化")
        else:
            print(f"[BackupManager] ✗ 无法初始化清单密钥管理器：缺少密码")

    def _compute_encrypted_chunk_size(self):
        """动态计算本地金库落盘的加密块大小"""
        dummy_data = b'\0' * self.BLOCK_SIZE
        dummy_shares = SecretSplitter.split_secret(dummy_data, 2, 2)
        dummy_encrypted = self.vault_crypto.encrypt_chunk(dummy_shares[0][1])
        self.ENCRYPTED_CHUNK_SIZE = len(dummy_encrypted)
        print(f"[BackupManager] ✓ 加密块大小已计算: {self.ENCRYPTED_CHUNK_SIZE} 字节")

    def set_progress_callback(self, callback: Callable[[str, int, int, float, str], None]):
        """设置进度更新回调函数
        
        Args:
            callback: (file_hash, processed, total, progress_percent, estimated_time)
        """
        self.on_progress_update = callback

    def _load_progress_state(self, file_hash: str, n: int) -> Dict:
        """加载之前的进度状态，支持断点续传"""
        progress_file = os.path.join(self.vault_dir, f".{file_hash}_progress.json")
        if os.path.exists(progress_file):
            try:
                with open(progress_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[BackupManager] 加载进度文件失败: {e}")
        return {
            "file_hash": file_hash,
            "completed_chunks": [[] for _ in range(n+1)],  # 索引从1开始
            "start_timestamp": time.time()
        }

    def _save_progress_state(self, state: Dict):
        """保存进度状态"""
        file_hash = state["file_hash"]
        progress_file = os.path.join(self.vault_dir, f".{file_hash}_progress.json")
        with open(progress_file, 'w') as f:
            json.dump(state, f)

    def _clear_progress_state(self, file_hash: str):
        """清除进度状态"""
        progress_file = os.path.join(self.vault_dir, f".{file_hash}_progress.json")
        if os.path.exists(progress_file):
            os.remove(progress_file)

    def _update_progress(self, file_hash: str, processed: int, total: int, state: Dict):
        """更新进度并调用回调"""
        progress = processed / total * 100
        elapsed = time.time() - state.get("start_timestamp", time.time())
        estimated = "计算中..."
        if elapsed > 0 and processed > 0:
            total_time_est = elapsed * total / processed
            remaining = max(0, total_time_est - elapsed)
            if remaining < 60:
                estimated = f"{remaining:.0f}秒"
            elif remaining < 3600:
                minutes = remaining / 60
                estimated = f"{minutes:.1f}分钟"
            else:
                hours = remaining / 3600
                estimated = f"{hours:.1f}小时"
        
        if self.on_progress_update:
            self.on_progress_update(file_hash, processed, total, progress, estimated)

    def execute_backup(self, filepath: str, n: int, t: int, resume: bool = True) -> str:
        """执行文件备份（双层切片架构）
        
        Args:
            filepath: 要备份的文件路径
            n: 总份额数
            t: 恢复阈值
            resume: 是否支持断点续传（默认True）
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError("文件不存在")

        file_size = os.path.getsize(filepath)
        total_chunks = max(1, (file_size + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE)
        
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()

        # 加载或初始化进度状态
        progress_state = self._load_progress_state(file_hash, n) if resume else self._load_progress_state(file_hash, n)
        completed_chunks = progress_state.get("completed_chunks", [[] for _ in range(n+1)])
        while len(completed_chunks) <= n:
            completed_chunks.append([])
        
        # 清理已存在的不完整文件（如果不是续传）
        if not resume:
            for i in range(1, n + 1):
                path = os.path.join(self.vault_dir, f"{file_hash}_share_{i}.dat")
                if os.path.exists(path):
                    os.remove(path)

        manifest_dict = {
            "filename": os.path.basename(filepath),
            "original_filename": os.path.basename(filepath),
            "original_hash": file_hash,
            "file_size": file_size,
            "n": n,
            "t": t,
            "local_shares": [],
            "remote_shares": []
        }
        
        # 获取所有已建立的安全连接
        secure_links = {}
        if hasattr(self.p2p_node, 'secure_links'):
            secure_links = self.p2p_node.secure_links
        
        # 确定哪些份额发给哪些节点（分配策略：本地优先，剩余的按顺序分发给连接的节点）
        share_distribution = {}
        local_indices = []
        available_remote_addrs = list(secure_links.keys()) if secure_links else []
        
        # 策略：份额 1 保留本地，剩余的优先分配给远程节点
        remote_idx = 0
        for i in range(1, n + 1):
            if i == 1:
                # 份额1总是保留本地
                local_indices.append(i)
            elif remote_idx < len(available_remote_addrs):
                # 分配给远程节点
                peer_addr = available_remote_addrs[remote_idx]
                share_distribution[i] = peer_addr
                remote_idx += 1
            else:
                # 没有更多远程节点，保留本地
                local_indices.append(i)
        
        print(f"[BackupManager] 份额分配: 本地={local_indices}, 远程={share_distribution}")
        start_time = time.time()
        
        with open(filepath, "rb") as f:
            for chunk_idx in range(total_chunks):
                # 检查是否已完成此分块
                all_completed = True
                for share_idx in range(1, n+1):
                    if chunk_idx not in completed_chunks[share_idx]:
                        all_completed = False
                        break
                if all_completed and resume:
                    continue
                
                # 1. 每次汲取 1MB 级别的大数据块
                chunk_data = f.read(self.BLOCK_SIZE)
                
                # 2. 尾部对齐补零
                if len(chunk_data) < self.BLOCK_SIZE:
                    chunk_data = chunk_data.ljust(self.BLOCK_SIZE, b'\0')
                
                # 3. O(1) 性能的混合加密切片
                shares = SecretSplitter.split_secret(chunk_data, t, n)

                for share_idx, share_data in shares:
                    if share_idx in share_distribution:
                        # 分发给远程节点
                        peer_addr = share_distribution[share_idx]
                        secure_link = secure_links[peer_addr]
                        
                        # 4. 计算当前 1MB 份额需要被切割成多少个 1KB 的网络碎片
                        total_frags = (len(share_data) + self.FRAGMENT_SIZE - 1) // self.FRAGMENT_SIZE
                        
                        for frag_idx in range(total_frags):
                            # 提取 1KB 碎片载荷
                            start_pos = frag_idx * self.FRAGMENT_SIZE
                            end_pos = start_pos + self.FRAGMENT_SIZE
                            frag_data = share_data[start_pos:end_pos]
                            
                            # 构建包含碎片定界信息的元数据
                            payload = {
                                "file_hash": file_hash,
                                "share_index": share_idx,
                                "chunk_index": chunk_idx,       # 所属的 1MB 大块索引
                                "total_chunks": total_chunks,
                                "frag_index": frag_idx,         # 当前的 1KB 碎片索引
                                "total_frags": total_frags      # 该大块的总碎片数
                            }
                            
                            # 生成分离式封包
                            msg = AppMessageV2(
                                cmd=AppCmdV2.SHARE_PUSH,
                                sender_id=self.p2p_node.node_id,
                                payload=payload,
                                raw_payload=frag_data
                            )
                            
                            # 5. 基于拥塞控制的事件驱动流控
                            cc = getattr(secure_link, 'cc', None) or getattr(secure_link, 'congestion_control', None)
                            cwnd_packets = max(10, cc.get_cwnd_packets()) if cc else 100
                            
                            secure_link.rudp.wait_for_window(cwnd_packets)
                            secure_link.send_reliable(msg.encode())
                            
                        # 记录已完成的分块
                        completed_chunks[share_idx].append(chunk_idx)
                    else:
                        # 本地保存
                        self._save_share_locally(file_hash, share_idx, share_data, chunk_idx)
                        completed_chunks[share_idx].append(chunk_idx)
                
                # 更新进度和保存状态
                progress_state["completed_chunks"] = completed_chunks
                self._save_progress_state(progress_state)
                self._update_progress(file_hash, chunk_idx + 1, total_chunks, progress_state)

        # 备份完成，清理进度文件
        self._clear_progress_state(file_hash)
        
        # 更新清单信息
        manifest_dict["local_shares"] = local_indices
        for share_idx, peer_addr in share_distribution.items():
            manifest_dict["remote_shares"].append({
                "index": share_idx,
                "peer": str(peer_addr)
            })

        # 只保存加密的清单文件，不保存明文 JSON
        raw_manifest_bytes = json.dumps(manifest_dict).encode('utf-8')
        
        # 1. 先加密一份发送者自己用的版本（用自己的公钥）
        encrypted_manifest_for_sender = None
        if self.manifest_key_manager:
            print(f"[BackupManager] 使用发送者本地公钥加密清单（自用备份）")
            encrypted_manifest_for_sender = self.manifest_key_manager.encrypt_manifest(
                raw_manifest_bytes, self.manifest_key_manager.get_public_key()
            )
        else:
            encrypted_manifest_for_sender = self.vault_crypto.encrypt_manifest(raw_manifest_bytes)
        
        session_id = os.urandom(8).hex()
        
        # 保存发送者自己用的加密清单到本地
        encrypted_manifest_path = os.path.join(self.vault_dir, f"{session_id}.enc")
        with open(encrypted_manifest_path, "wb") as f:
            f.write(encrypted_manifest_for_sender)
        
        # 2. 为每个远程节点生成用其公钥加密的清单并发送
        for share_idx, peer_addr in share_distribution.items():
            secure_link = secure_links[peer_addr]
            
            # 获取该节点的清单加密公钥
            recipient_pk = None
            
            # a. 首先从安全通道获取（当前会话）
            if hasattr(secure_link, 'channel') and hasattr(secure_link.channel, 'peer_manifest_pk'):
                recipient_pk = secure_link.channel.peer_manifest_pk
            
            # b. 如果当前会话没有，尝试从持久化存储中查找
            if not recipient_pk and self.manifest_key_manager:
                # 尝试用节点地址查找
                recipient_pk = self.manifest_key_manager.get_peer_public_key(str(peer_addr))
                if not recipient_pk and hasattr(secure_link, 'channel') and hasattr(secure_link.channel, 'remote_node_id'):
                    # 尝试用远程节点ID查找
                    recipient_pk = self.manifest_key_manager.get_peer_public_key(secure_link.channel.remote_node_id)
            
            # c. 生成用该节点公钥加密的清单
            if recipient_pk and self.manifest_key_manager:
                print(f"[BackupManager] 使用节点 {peer_addr} 的公钥加密清单")
                encrypted_manifest_for_peer = self.manifest_key_manager.encrypt_manifest(
                    raw_manifest_bytes, recipient_pk
                )
            else:
                print(f"[BackupManager] 未找到节点 {peer_addr} 的公钥，使用发送者公钥加密（回退模式）")
                encrypted_manifest_for_peer = encrypted_manifest_for_sender
            
            # 发送给该节点
            secure_manifest_b64 = base64.b64encode(encrypted_manifest_for_peer).decode('utf-8')
            
            payload = {
                "session_id": session_id,
                "secure_manifest": secure_manifest_b64,
                "file_hash": file_hash,
                "share_index": share_idx
            }
            msg = AppMessageV2(
                cmd=AppCmdV2.SHARE_PUSH,
                sender_id=self.p2p_node.node_id,
                payload=payload
            )
            secure_link.send_reliable(msg.encode())

        elapsed = time.time() - start_time
        print(f"[BackupManager] 备份完成！耗时: {elapsed:.2f}秒")
        return encrypted_manifest_path

    def _save_share_locally(self, file_hash: str, index: int, data: bytes, chunk_idx: int = 0):
        """保存份额到本地，支持分块写入"""
        path = os.path.join(self.vault_dir, f"{file_hash}_share_{index}.dat")
        encrypted_data = self.vault_crypto.encrypt_chunk(data)
        mode = "r+b" if os.path.exists(path) else "wb"
        with open(path, mode) as f:
            f.seek(chunk_idx * self.ENCRYPTED_CHUNK_SIZE)
            f.write(encrypted_data)

    def handle_incoming_share(self, peer_addr: tuple, msg: AppMessageV2):
        """处理收到的份额（双层切片接收端：碎片内存拼装，单次大块落盘）"""
        if msg.cmd != AppCmdV2.SHARE_PUSH:
            return
            
        # 提取清单盲存数据（若有）
        session_id = msg.payload.get("session_id")
        secure_manifest_b64 = msg.payload.get("secure_manifest")
        
        # 提取文件元数据及双层定界信息
        file_hash = msg.payload.get("file_hash")
        share_index = msg.payload.get("share_index")
        chunk_index = msg.payload.get("chunk_index", 0)
        total_chunks = msg.payload.get("total_chunks", 1)
        
        # 获取碎片信息
        frag_index = msg.payload.get("frag_index", 0)
        total_frags = msg.payload.get("total_frags", 1)
        
        share_data_frag = msg.raw_payload

        if share_data_frag:
            if not file_hash or share_index is None:
                print(f"[Vault] 收到不完整的份额元数据: file_hash={file_hash}, share_index={share_index}")
                return
            
            # 构建该 1MB 大块的唯一缓冲键名
            buf_key = f"{file_hash}_{share_index}_{chunk_index}"
            
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
                
            # 【核心屏障】当该 1MB 大块的所有碎片收集完毕时，触发合并与落盘
            if buf["received"] == buf["total"]:
                # 按索引严格按序拼装成 1MB 原始加密份额
                full_share_data = b"".join(buf["frags"][i] for i in range(buf["total"]))
                
                # 释放内存
                del self.frag_buffers[buf_key]
                
                # 仅对完整的 1MB 块进行一次本地金库加密
                encrypted_data = self.vault_crypto.encrypt_chunk(full_share_data)
                
                dat_path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_index}.dat")
                mode = "r+b" if os.path.exists(dat_path) else "wb"
                
                with open(dat_path, mode) as f:
                    # 使用精确的 1MB 级定长偏移量写入
                    f.seek(chunk_index * self.ENCRYPTED_CHUNK_SIZE)
                    f.write(encrypted_data)
                    
                if chunk_index == total_chunks - 1:
                    print(f"[Vault] 成功接收并【本地加密保管】资产份额 (序号: {share_index})")

        # 处理 manifest 落盘的逻辑保持不变
        if secure_manifest_b64 and session_id:
            from src.config import MANIFESTS_DIR
            
            os.makedirs(MANIFESTS_DIR, exist_ok=True)
            
            manifest_path = os.path.join(MANIFESTS_DIR, f"{session_id}.enc")
            
            try:
                encrypted_manifest_bytes = base64.b64decode(secure_manifest_b64)
                with open(manifest_path, "wb") as f:
                    f.write(encrypted_manifest_bytes)
                print(f"[BackupManager] 加密清单已盲存: {session_id}.enc")
            except Exception as e:
                print(f"[BackupManager] 加密清单落盘失败: {e}")
