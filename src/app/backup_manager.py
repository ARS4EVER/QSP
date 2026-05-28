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
    BLOCK_SIZE = 1024 * 1024
    FRAGMENT_SIZE = 1024

    def __init__(self, p2p_node, vault_crypto, vault_dir: str = "./data/shares"):
        self.p2p_node = p2p_node
        self.vault_dir = vault_dir
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)
            
        self.vault_crypto = vault_crypto
        self.manifest_key_manager = None
        
        self.on_progress_update: Optional[Callable[[str, int, int, float, str], None]] = None
        
        self.frag_buffers = {}
        
        self._init_manifest_key_manager()
        
        self._compute_encrypted_chunk_size()

    def _init_manifest_key_manager(self):
        if hasattr(self.vault_crypto, 'password'):
            password = self.vault_crypto.password.decode('utf-8') if isinstance(self.vault_crypto.password, bytes) else self.vault_crypto.password
            self.manifest_key_manager = ManifestKeyManager(password)
            print(f"[BackupManager] ✓ 清单密钥管理器已初始化")
        else:
            print(f"[BackupManager] ✗ 无法初始化清单密钥管理器：缺少密码")

    def _compute_encrypted_chunk_size(self):
        dummy_data = b'\0' * self.BLOCK_SIZE
        dummy_shares = SecretSplitter.split_secret(dummy_data, 2, 2)
        dummy_encrypted = self.vault_crypto.encrypt_chunk(dummy_shares[0][1])
        self.ENCRYPTED_CHUNK_SIZE = len(dummy_encrypted)
        print(f"[BackupManager] ✓ 加密块大小已计算: {self.ENCRYPTED_CHUNK_SIZE} 字节")

    def set_progress_callback(self, callback: Callable[[str, int, int, float, str], None]):
        self.on_progress_update = callback

    def _load_progress_state(self, file_hash: str, n: int) -> Dict:
        progress_file = os.path.join(self.vault_dir, f".{file_hash}_progress.json")
        if os.path.exists(progress_file):
            try:
                with open(progress_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[BackupManager] 加载进度文件失败: {e}")
        return {
            "file_hash": file_hash,
            "completed_chunks": [[] for _ in range(n+1)],
            "start_timestamp": time.time()
        }

    def _save_progress_state(self, state: Dict):
        file_hash = state["file_hash"]
        progress_file = os.path.join(self.vault_dir, f".{file_hash}_progress.json")
        with open(progress_file, 'w') as f:
            json.dump(state, f)

    def _clear_progress_state(self, file_hash: str):
        progress_file = os.path.join(self.vault_dir, f".{file_hash}_progress.json")
        if os.path.exists(progress_file):
            os.remove(progress_file)

    def _update_progress(self, file_hash: str, processed: int, total: int, state: Dict):
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
        if not os.path.exists(filepath):
            raise FileNotFoundError("文件不存在")

        file_size = os.path.getsize(filepath)
        total_chunks = max(1, (file_size + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE)
        
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()

        progress_state = self._load_progress_state(file_hash, n) if resume else self._load_progress_state(file_hash, n)
        completed_chunks = progress_state.get("completed_chunks", [[] for _ in range(n+1)])
        while len(completed_chunks) <= n:
            completed_chunks.append([])
        
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
        
        remote_target_idx = 2 if len(range(n)) > 1 and getattr(self.p2p_node, 'secure_link', None) else None
        start_time = time.time()
        
        with open(filepath, "rb") as f:
            for chunk_idx in range(total_chunks):
                all_completed = True
                for share_idx in range(1, n+1):
                    if chunk_idx not in completed_chunks[share_idx]:
                        all_completed = False
                        break
                if all_completed and resume:
                    continue
                
                chunk_data = f.read(self.BLOCK_SIZE)
                
                if len(chunk_data) < self.BLOCK_SIZE:
                    chunk_data = chunk_data.ljust(self.BLOCK_SIZE, b'\0')
                
                shares = SecretSplitter.split_secret(chunk_data, t, n)

                for share_idx, share_data in shares:
                    if share_idx == remote_target_idx:
                        total_frags = (len(share_data) + self.FRAGMENT_SIZE - 1) // self.FRAGMENT_SIZE
                        
                        for frag_idx in range(total_frags):
                            start_pos = frag_idx * self.FRAGMENT_SIZE
                            end_pos = start_pos + self.FRAGMENT_SIZE
                            frag_data = share_data[start_pos:end_pos]
                            
                            payload = {
                                "file_hash": file_hash,
                                "share_index": share_idx,
                                "chunk_index": chunk_idx,
                                "total_chunks": total_chunks,
                                "frag_index": frag_idx,
                                "total_frags": total_frags
                            }
                            
                            msg = AppMessageV2(
                                cmd=AppCmdV2.SHARE_PUSH,
                                sender_id=self.p2p_node.node_id,
                                payload=payload,
                                raw_payload=frag_data
                            )
                            
                            secure_link = self.p2p_node.secure_link
                            cc = getattr(secure_link, 'cc', None) or getattr(secure_link, 'congestion_control', None)
                            cwnd_packets = max(10, cc.get_cwnd_packets()) if cc else 100
                            
                            secure_link.rudp.wait_for_window(cwnd_packets)
                            secure_link.send_reliable(msg.encode())
                            
                        completed_chunks[share_idx].append(chunk_idx)
                    else:
                        self._save_share_locally(file_hash, share_idx, share_data, chunk_idx)
                        completed_chunks[share_idx].append(chunk_idx)
                
                progress_state["completed_chunks"] = completed_chunks
                self._save_progress_state(progress_state)
                self._update_progress(file_hash, chunk_idx + 1, total_chunks, progress_state)

        self._clear_progress_state(file_hash)
        
        for i in range(1, n + 1):
            if i == remote_target_idx:
                manifest_dict["remote_shares"].append({
                    "index": i,
                    "peer": str(self.p2p_node.peer_addr)
                })
            else:
                manifest_dict["local_shares"].append(i)

        raw_manifest_bytes = json.dumps(manifest_dict).encode('utf-8')
        
        encrypted_manifest_for_sender = None
        encrypted_manifest_for_recipient = None
        
        recipient_pk = None
        
        if hasattr(self.p2p_node, 'secure_link') and hasattr(self.p2p_node.secure_link, 'channel'):
            channel = self.p2p_node.secure_link.channel
            if hasattr(channel, 'peer_manifest_pk'):
                recipient_pk = channel.peer_manifest_pk
        
        if not recipient_pk and self.manifest_key_manager and hasattr(self.p2p_node, 'peer_addr'):
            peer_addr = self.p2p_node.peer_addr
            recipient_pk = self.manifest_key_manager.get_peer_public_key(str(peer_addr))
        
        if not recipient_pk and self.manifest_key_manager and hasattr(self.p2p_node, 'secure_link'):
            channel = self.p2p_node.secure_link.channel if hasattr(self.p2p_node.secure_link, 'channel') else None
            if channel and hasattr(channel, 'remote_node_id') and channel.remote_node_id:
                recipient_pk = self.manifest_key_manager.get_peer_public_key(channel.remote_node_id)
        
        if self.manifest_key_manager:
            print(f"[BackupManager] 使用发送者本地公钥加密清单（自用备份）")
            encrypted_manifest_for_sender = self.manifest_key_manager.encrypt_manifest(
                raw_manifest_bytes, self.manifest_key_manager.get_public_key()
            )
        else:
            encrypted_manifest_for_sender = self.vault_crypto.encrypt_manifest(raw_manifest_bytes)
        
        if recipient_pk and self.manifest_key_manager:
            print(f"[BackupManager] 使用接收者公钥加密清单")
            encrypted_manifest_for_recipient = self.manifest_key_manager.encrypt_manifest(
                raw_manifest_bytes, recipient_pk
            )
        else:
            print(f"[BackupManager] 未找到接收者公钥，使用发送者公钥加密发送（回退模式）")
            encrypted_manifest_for_recipient = encrypted_manifest_for_sender
        
        secure_manifest_b64 = base64.b64encode(encrypted_manifest_for_recipient).decode('utf-8')

        session_id = os.urandom(8).hex()
        
        encrypted_manifest_path = os.path.join(self.vault_dir, f"{session_id}.enc")
        with open(encrypted_manifest_path, "wb") as f:
            f.write(encrypted_manifest_for_sender)

        if remote_target_idx and hasattr(self.p2p_node, 'secure_link'):
            payload = {
                "session_id": session_id,
                "secure_manifest": secure_manifest_b64,
                "file_hash": file_hash,
                "share_index": remote_target_idx
            }
            msg = AppMessageV2(
                cmd=AppCmdV2.SHARE_PUSH,
                sender_id=self.p2p_node.node_id,
                payload=payload
            )
            self.p2p_node.secure_link.send_reliable(msg.encode())

        elapsed = time.time() - start_time
        print(f"[BackupManager] 备份完成！耗时: {elapsed:.2f}秒")
        return encrypted_manifest_path

    def _save_share_locally(self, file_hash: str, index: int, data: bytes, chunk_idx: int = 0):
        path = os.path.join(self.vault_dir, f"{file_hash}_share_{index}.dat")
        encrypted_data = self.vault_crypto.encrypt_chunk(data)
        mode = "r+b" if os.path.exists(path) else "wb"
        with open(path, mode) as f:
            f.seek(chunk_idx * self.ENCRYPTED_CHUNK_SIZE)
            f.write(encrypted_data)

    def handle_incoming_share(self, peer_addr: tuple, msg: AppMessageV2):
        if msg.cmd != AppCmdV2.SHARE_PUSH:
            return
            
        session_id = msg.payload.get("session_id")
        secure_manifest_b64 = msg.payload.get("secure_manifest")
        
        file_hash = msg.payload.get("file_hash")
        share_index = msg.payload.get("share_index")
        chunk_index = msg.payload.get("chunk_index", 0)
        total_chunks = msg.payload.get("total_chunks", 1)
        
        frag_index = msg.payload.get("frag_index", 0)
        total_frags = msg.payload.get("total_frags", 1)
        
        share_data_frag = msg.raw_payload

        if share_data_frag:
            if not file_hash or share_index is None:
                print(f"[Vault] 收到不完整的份额元数据: file_hash={file_hash}, share_index={share_index}")
                return
            
            buf_key = f"{file_hash}_{share_index}_{chunk_index}"
            
            if buf_key not in self.frag_buffers:
                self.frag_buffers[buf_key] = {
                    "frags": {},
                    "received": 0,
                    "total": total_frags
                }
                
            buf = self.frag_buffers[buf_key]
            
            if frag_index not in buf["frags"]:
                buf["frags"][frag_index] = share_data_frag
                buf["received"] += 1
                
            if buf["received"] == buf["total"]:
                full_share_data = b"".join(buf["frags"][i] for i in range(buf["total"]))
                
                del self.frag_buffers[buf_key]
                
                encrypted_data = self.vault_crypto.encrypt_chunk(full_share_data)
                
                dat_path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_index}.dat")
                mode = "r+b" if os.path.exists(dat_path) else "wb"
                
                with open(dat_path, mode) as f:
                    f.seek(chunk_index * self.ENCRYPTED_CHUNK_SIZE)
                    f.write(encrypted_data)
                    
                if chunk_index == total_chunks - 1:
                    print(f"[Vault] 成功接收并【本地加密保管】资产份额 (序号: {share_index})")

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
