import os
import json
import hashlib
import time
from typing import Optional

import base64
from src.app.app_protocol import AppMessage, AppCmd, AppMessageV2, AppCmdV2
from src.secret_sharing.splitter import SecretSplitter
from src.app.vault_crypto import VaultCrypto

class BackupManager:
    CHUNK_SIZE = 512
    ENCRYPTED_CHUNK_SIZE = 540  # 512 + 12(Nonce) + 16(Tag)

    def __init__(self, p2p_node, vault_crypto, vault_dir: str = "./data/shares"):
        self.p2p_node = p2p_node
        self.vault_dir = vault_dir
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)
            
        self.vault_crypto = vault_crypto

    def execute_backup(self, filepath: str, n: int, t: int) -> str:
        if not os.path.exists(filepath):
            raise FileNotFoundError("文件不存在")

        file_size = os.path.getsize(filepath)
        total_chunks = max(1, (file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE)
        
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()

        for i in range(1, n + 1):
            path = os.path.join(self.vault_dir, f"{file_hash}_share_{i}.dat")
            if os.path.exists(path):
                os.remove(path)

        manifest = {
            "filename": os.path.basename(filepath),
            "original_hash": file_hash,
            "n": n,
            "t": t,
            "local_shares": [],
            "remote_shares": []
        }
        
        remote_target_idx = 2 if len(range(n)) > 1 and getattr(self.p2p_node, 'secure_link', None) else None

        with open(filepath, "rb") as f:
            for chunk_idx in range(total_chunks):
                chunk_data = f.read(self.CHUNK_SIZE)
                shares = SecretSplitter.split_secret(chunk_data, t, n)

                for share_idx, share_data in shares:
                    if share_idx == remote_target_idx:
                        share_data_b64 = base64.b64encode(share_data).decode('utf-8')
                        payload = {
                            "file_hash": file_hash,
                            "share_index": share_idx,
                            "share_data_b64": share_data_b64,
                            "chunk_index": chunk_idx,
                            "total_chunks": total_chunks
                        }
                        msg = AppMessageV2(
                            cmd=AppCmdV2.SHARE_PUSH,
                            sender_id=self.p2p_node.node_id,
                            payload=payload
                        )
                        self.p2p_node.secure_link.send_reliable(msg.encode())
                        
                        while len(self.p2p_node.secure_link.rudp.unacked_packets) > 80:
                            time.sleep(0.01)
                    else:
                        self._save_share_locally(file_hash, share_idx, share_data)

        for i in range(1, n + 1):
            if i == remote_target_idx:
                manifest["remote_shares"].append({
                    "index": i,
                    "peer": str(self.p2p_node.peer_addr)
                })
            else:
                manifest["local_shares"].append(i)

        manifest_path = os.path.join(self.vault_dir, f"{file_hash[:8]}_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4)
        return manifest_path

    def _save_share_locally(self, file_hash: str, index: int, data: bytes):
        path = os.path.join(self.vault_dir, f"{file_hash}_share_{index}.dat")
        encrypted_data = self.vault_crypto.encrypt_chunk(data)
        with open(path, "ab") as f:
            f.write(encrypted_data)

    def handle_incoming_share(self, peer_addr: tuple, msg: AppMessageV2):
        if msg.cmd != AppCmdV2.SHARE_PUSH:
            return
        
        file_hash = msg.payload.get("file_hash")
        share_index = msg.payload.get("share_index")
        share_data_b64 = msg.payload.get("share_data_b64")
        chunk_index = msg.payload.get("chunk_index", 0)
        total_chunks = msg.payload.get("total_chunks", 1)
        
        if not file_hash or share_index is None or not share_data_b64:
            print(f"[Vault] 收到不完整的份额数据: file_hash={file_hash}, share_index={share_index}")
            return
        
        try:
            share_data = base64.b64decode(share_data_b64)
        except Exception as e:
            print(f"[Vault] Base64 解码失败: {e}")
            return
        
        dat_path = os.path.join(self.vault_dir, f"{file_hash}_share_{share_index}.dat")
        encrypted_data = self.vault_crypto.encrypt_chunk(share_data)
        
        mode = "r+b" if os.path.exists(dat_path) else "wb"
        with open(dat_path, mode) as f:
            f.seek(chunk_index * self.ENCRYPTED_CHUNK_SIZE)
            f.write(encrypted_data)
            
        if chunk_index == total_chunks - 1:
            print(f"[Vault] 成功接收并【本地加密保管】资产份额 (序号: {share_index})")
