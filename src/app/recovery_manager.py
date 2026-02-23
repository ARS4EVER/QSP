"""
src/app/recovery_manager.py
[Phase 10] 资产恢复流水线 (本地金库加密版)
"""
import os
import json
import hashlib
import time
from typing import Dict, List, Tuple

from src.app.app_protocol import AppMessage, AppCmd
from src.secret_sharing.reconstructor import SecretReconstructor
from src.app.vault_crypto import VaultCrypto

class RecoveryManager:
    CHUNK_SIZE = 512
    ENCRYPTED_CHUNK_SIZE = 540

    def __init__(self, p2p_node, vault_password: str = "default_secure_password", vault_dir: str = "./vault"):
        self.p2p_node = p2p_node
        self.vault_dir = vault_dir
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)
            
        self.vault_crypto = VaultCrypto(vault_password, self.vault_dir)
        self.active_manifests: Dict[str, dict] = {}
        
        self.on_progress_update = None  
        self.on_recovery_success = None 
        self.on_recovery_failed = None  

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

        msg = AppMessage(cmd=AppCmd.PULL_REQ, file_hash=file_hash)
        if getattr(self.p2p_node, 'secure_link', None):
            try:
                self.p2p_node.secure_link.send_reliable(msg.pack())
                print(f"[Recovery] 份额不足 ({current_shares}/{t})，已发送网络拉取请求...")
            except Exception as e:
                self._trigger_fail(file_hash, f"网络发送失败: {e}")
        else:
            self._trigger_fail(file_hash, "份额不足且无抗量子网络连接！")

    def handle_pull_request(self, peer_addr: tuple, msg: AppMessage):
        if msg.cmd != AppCmd.PULL_REQ: return
        local_shares = self.load_local_shares(msg.file_hash)
        
        if not local_shares or not getattr(self.p2p_node, 'secure_link', None):
            error_msg = AppMessage(cmd=AppCmd.ERROR, file_hash=msg.file_hash, error_msg="未找到份额")
            self.p2p_node.secure_link.send_reliable(error_msg.pack())
            return
            
        share_idx = local_shares[0]
        path = os.path.join(self.vault_dir, f"{msg.file_hash}_share_{share_idx}.dat")
        file_size = os.path.getsize(path)
        total_chunks = max(1, (file_size + self.ENCRYPTED_CHUNK_SIZE - 1) // self.ENCRYPTED_CHUNK_SIZE)
        
        with open(path, "rb") as f:
            for chunk_idx in range(total_chunks):
                encrypted_chunk = f.read(self.ENCRYPTED_CHUNK_SIZE)
                if not encrypted_chunk: break
                
                try:
                    # 【核心修改】从磁盘读出时先透明解密，再交给网络传输
                    chunk_data = self.vault_crypto.decrypt_chunk(encrypted_chunk)
                except Exception as e:
                    print(f"[Vault] 解析本地份额失败，拒绝传输: {e}")
                    break
                
                resp_msg = AppMessage(
                    cmd=AppCmd.PULL_RESP, file_hash=msg.file_hash, 
                    share_index=share_idx, share_data=chunk_data, 
                    chunk_index=chunk_idx, total_chunks=total_chunks
                )
                self.p2p_node.secure_link.send_reliable(resp_msg.pack())
                
                while len(self.p2p_node.secure_link.rudp.unacked_packets) > 80:
                    time.sleep(0.01)

    def handle_pull_response(self, peer_addr: tuple, msg: AppMessage):
        if msg.cmd != AppCmd.PULL_RESP or not msg.share_data: return
        
        file_hash = msg.file_hash
        share_idx = msg.share_index
        
        if share_idx in self.load_local_shares(file_hash): return
        
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
                
        if msg.chunk_index in received_chunks:
            return 
            
        # 【核心修改】将收到的网络包立刻加密
        encrypted_data = self.vault_crypto.encrypt_chunk(msg.share_data)
            
        mode = "r+b" if os.path.exists(part_path) else "wb"
        with open(part_path, mode) as f:
            # 步长由 512 膨胀为 540
            f.seek(msg.chunk_index * self.ENCRYPTED_CHUNK_SIZE)
            f.write(encrypted_data)
            
        received_chunks.add(msg.chunk_index)
        
        with open(meta_path, "w") as f:
            json.dump({
                "total_chunks": msg.total_chunks, 
                "received": list(received_chunks)
            }, f)
            
        if len(received_chunks) >= msg.total_chunks:
            dat_path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_idx}.dat")
            os.rename(part_path, dat_path)
            os.remove(meta_path)
            print(f"[Vault] 资产份额 {share_idx} 极速下载与【本地加密】完成！")
            
            if file_hash in self.active_manifests:
                t = self.active_manifests[file_hash]["t"]
                local_indices = self.load_local_shares(file_hash)
                
                if self.on_progress_update:
                    self.on_progress_update(file_hash, len(local_indices), t)
                    
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
        
        try:
            file_handles = []
            for idx in share_indices[:t]:
                path = os.path.join(self.vault_dir, f"{file_hash}_share_{idx}.dat")
                file_handles.append((idx, open(path, "rb")))
                
            hasher = hashlib.sha256()
            
            with open(restored_path, "wb") as out_f:
                while True:
                    chunk_shares = []
                    for idx, fh in file_handles:
                        # 从磁盘取出膨胀的 540 字节块
                        encrypted_chunk = fh.read(self.ENCRYPTED_CHUNK_SIZE)
                        if encrypted_chunk:
                            try:
                                # 【核心修改】解密出干净的 512 字节明文切片
                                chunk = self.vault_crypto.decrypt_chunk(encrypted_chunk)
                                chunk_shares.append((idx, chunk))
                            except Exception as e:
                                raise ValueError(f"金库数据解密失败，可能是密码错误或数据已损坏: {e}")
                            
                    if len(chunk_shares) < t or len(chunk_shares[0][1]) == 0:
                        break 
                        
                    recovered_chunk = SecretReconstructor.reconstruct(chunk_shares)
                    
                    out_f.write(recovered_chunk)
                    hasher.update(recovered_chunk)
                    
            for _, fh in file_handles: fh.close()
            
            if hasher.hexdigest() != manifest["original_hash"]:
                raise ValueError("数据完整性受损：哈希校验不匹配，文件可能遭到了篡改！")
                
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
