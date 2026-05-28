"""
清单密钥管理器

管理清单加密密钥的生成、存储和点对点交换
使用 Kyber KEM 实现抗量子密钥封装
"""

import os
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from src.crypto_lattice.encryptor import KyberKEM
from src.config import KEYS_DIR


class ManifestKeyManager:
    """
    清单密钥管理器
    
    生成并安全管理用于加密清单数据的密钥对
    支持与其他节点交换公钥并进行端到端加密通信
    """
    
    KEY_FILE = "manifest_key.json"
    PEER_KEYS_FILE = "peer_manifest_keys.json"
    
    def __init__(self, vault_password: str):
        self.vault_password = vault_password.encode('utf-8')
        self.public_key = None
        self.private_key = None
        self.key_path = os.path.join(KEYS_DIR, self.KEY_FILE)
        self.peer_keys_path = os.path.join(KEYS_DIR, self.PEER_KEYS_FILE)
        self.peer_keys = {}
        
        self._load_or_generate_keys()
        self._load_peer_keys()
    
    def _derive_storage_key(self, salt: bytes) -> bytes:
        """使用 PBKDF2 从主密码派生存储密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.vault_password)
    
    def _load_or_generate_keys(self):
        """加载现有密钥或生成新密钥对"""
        if os.path.exists(self.key_path):
            self._load_keys()
        else:
            self._generate_and_save_keys()
    
    def _generate_and_save_keys(self):
        """生成新的 Kyber 密钥对并加密保存"""
        print(f"[ManifestKeyManager] 生成新的清单加密密钥对...")
        
        public_key, private_key = KyberKEM.generate_keypair()
        
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        storage_key = self._derive_storage_key(salt)
        aesgcm = AESGCM(storage_key)
        
        encrypted_private_key = aesgcm.encrypt(nonce, private_key, None)
        
        data = {
            "public_key": public_key.hex(),
            "encrypted_private_key": encrypted_private_key.hex(),
            "salt": salt.hex(),
            "nonce": nonce.hex()
        }
        
        with open(self.key_path, 'w') as f:
            json.dump(data, f)
        
        self.public_key = public_key
        self.private_key = private_key
        
        print(f"[ManifestKeyManager] ✓ 密钥对已生成并保存")
    
    def _load_keys(self):
        """从文件加载并解密密钥对"""
        print(f"[ManifestKeyManager] 加载清单加密密钥...")
        
        try:
            with open(self.key_path, 'r') as f:
                data = json.load(f)
            
            self.public_key = bytes.fromhex(data['public_key'])
            encrypted_private_key = bytes.fromhex(data['encrypted_private_key'])
            salt = bytes.fromhex(data['salt'])
            nonce = bytes.fromhex(data['nonce'])
            
            storage_key = self._derive_storage_key(salt)
            aesgcm = AESGCM(storage_key)
            self.private_key = aesgcm.decrypt(nonce, encrypted_private_key, None)
            
            print(f"[ManifestKeyManager] ✓ 密钥对已加载")
        except Exception as e:
            print(f"[ManifestKeyManager] ✗ 加载密钥失败: {e}")
            self._generate_and_save_keys()
    
    def _load_peer_keys(self):
        """加载其他节点的公钥"""
        print(f"[ManifestKeyManager] 加载节点公钥存储...")
        
        try:
            if os.path.exists(self.peer_keys_path):
                with open(self.peer_keys_path, 'r') as f:
                    data = json.load(f)
                
                self.peer_keys = {
                    node_id: bytes.fromhex(pk_hex)
                    for node_id, pk_hex in data.items()
                }
                print(f"[ManifestKeyManager] ✓ 已加载 {len(self.peer_keys)} 个节点公钥")
            else:
                self.peer_keys = {}
                print(f"[ManifestKeyManager] ✓ 节点公钥存储为空")
        except Exception as e:
            print(f"[ManifestKeyManager] ✗ 加载节点公钥失败: {e}")
            self.peer_keys = {}
    
    def _save_peer_keys(self):
        """保存节点公钥到文件"""
        try:
            data = {
                node_id: pk.hex()
                for node_id, pk in self.peer_keys.items()
            }
            
            with open(self.peer_keys_path, 'w') as f:
                json.dump(data, f)
            
            print(f"[ManifestKeyManager] ✓ 已保存 {len(self.peer_keys)} 个节点公钥")
        except Exception as e:
            print(f"[ManifestKeyManager] ✗ 保存节点公钥失败: {e}")
    
    def save_peer_public_key(self, node_id: str, public_key: bytes):
        """保存其他节点的公钥"""
        self.peer_keys[node_id] = public_key
        self._save_peer_keys()
    
    def get_peer_public_key(self, node_id: str) -> bytes:
        """获取指定节点的公钥"""
        return self.peer_keys.get(node_id)
    
    def remove_peer_public_key(self, node_id: str):
        """移除指定节点的公钥"""
        if node_id in self.peer_keys:
            del self.peer_keys[node_id]
            self._save_peer_keys()
    
    def list_peers(self) -> list:
        """列出所有已知节点 ID"""
        return list(self.peer_keys.keys())
    
    def get_public_key(self) -> bytes:
        """获取本节点公钥"""
        return self.public_key
    
    def get_private_key(self) -> bytes:
        """获取本节点私钥（谨慎使用）"""
        return self.private_key
    
    def encrypt_manifest(self, data: bytes, recipient_public_key: bytes) -> bytes:
        """
        使用接收者公钥加密清单数据（Kyber KEM 密钥封装）
        
        格式: VERSION(1) + Kyber密文 + AESGCM加密数据
        """
        ciphertext, shared_secret = KyberKEM.encapsulate(recipient_public_key)
        
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        
        return b'\x03' + ciphertext + nonce + encrypted_data
    
    def decrypt_manifest(self, encrypted_data: bytes) -> bytes:
        """使用本节点私钥解密清单数据"""
        if len(encrypted_data) < 2:
            raise ValueError("Encrypted manifest is too short")
        
        version = encrypted_data[0:1]
        if version != b'\x03':
            raise ValueError(f"Unsupported manifest version: {version}")
        
        ciphertext = encrypted_data[1:769]
        nonce = encrypted_data[769:781]
        encrypted_manifest = encrypted_data[781:]
        
        shared_secret = KyberKEM.decapsulate(ciphertext, self.private_key)
        
        aesgcm = AESGCM(shared_secret)
        try:
            return aesgcm.decrypt(nonce, encrypted_manifest, None)
        except InvalidTag as e:
            raise InvalidTag("[ManifestKeyManager] 清单解密失败：密钥不匹配或数据损坏！") from e
    
    def destroy(self):
        """安全销毁密钥数据"""
        if self.private_key:
            self.private_key = b'\x00' * len(self.private_key)
        if self.public_key:
            self.public_key = b'\x00' * len(self.public_key)
        self.vault_password = b""
        import gc
        gc.collect()
