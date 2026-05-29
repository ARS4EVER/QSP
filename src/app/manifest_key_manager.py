"""
清单加密密钥管理器

为每个节点生成专门用于清单加密的长期密钥对，确保：
1. 前向安全性 - 不保存临时会话密钥
2. 独立密钥空间 - 清单加密与通信加密分离
3. 量子安全 - 使用 ML-KEM-512 算法
"""

import os
import json
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from src.crypto_lattice.encryptor import KyberKEM
from src.config import KEYS_DIR


class ManifestKeyManager:
    """
    清单加密密钥管理器
    
    每个节点维护一对专门用于清单加密的长期密钥：
    - 公钥：分发给其他节点，用于加密清单
    - 私钥：本地保存，用于解密清单
    
    同时维护一个持久化的节点公钥存储，每个节点的公钥单独保存为一个文件。
    文件命名格式：peer_key_{node_id的SHA256哈希前16位}.json
    
    工作流程：
    1. 加载或生成密钥对
    2. 在安全信道内交换公钥并持久化存储
    3. 使用对端公钥加密清单
    4. 使用本地私钥解密清单
    """
    
    KEY_FILE = "manifest_key.json"
    PEER_KEYS_DIR = "peer_manifest_keys"
    
    def __init__(self, vault_password: str):
        """
        初始化密钥管理器
        
        Args:
            vault_password: 金库密码，用于加密私钥存储
        """
        self.vault_password = vault_password.encode('utf-8')
        self.public_key = None
        self.private_key = None
        self.key_path = os.path.join(KEYS_DIR, self.KEY_FILE)
        self.peer_keys_dir = os.path.join(KEYS_DIR, self.PEER_KEYS_DIR)
        self.peer_keys_cache = {}  # 内存缓存：节点身份指纹 -> 清单公钥
        
        self._ensure_peer_keys_dir()
        self._load_or_generate_keys()
        self._load_peer_keys()
    
    def _derive_storage_key(self, salt: bytes) -> bytes:
        """从金库密码派生存储密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.vault_password)
    
    def _load_or_generate_keys(self):
        """加载已存在的密钥或生成新密钥"""
        if os.path.exists(self.key_path):
            self._load_keys()
        else:
            self._generate_and_save_keys()
    
    def _generate_and_save_keys(self):
        """生成新密钥对并加密保存"""
        print(f"[ManifestKeyManager] 生成新的清单加密密钥对...")
        
        # 生成 Kyber 密钥对
        public_key, private_key = KyberKEM.generate_keypair()
        
        # 生成随机 salt 和 nonce
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        # 派生存储密钥
        storage_key = self._derive_storage_key(salt)
        aesgcm = AESGCM(storage_key)
        
        # 加密私钥
        encrypted_private_key = aesgcm.encrypt(nonce, private_key, None)
        
        # 保存到文件
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
        """加载并解密密钥"""
        print(f"[ManifestKeyManager] 加载清单加密密钥...")
        
        try:
            with open(self.key_path, 'r') as f:
                data = json.load(f)
            
            # 解析数据
            self.public_key = bytes.fromhex(data['public_key'])
            encrypted_private_key = bytes.fromhex(data['encrypted_private_key'])
            salt = bytes.fromhex(data['salt'])
            nonce = bytes.fromhex(data['nonce'])
            
            # 派生存储密钥并解密
            storage_key = self._derive_storage_key(salt)
            aesgcm = AESGCM(storage_key)
            self.private_key = aesgcm.decrypt(nonce, encrypted_private_key, None)
            
            print(f"[ManifestKeyManager] ✓ 密钥对已加载")
        except Exception as e:
            print(f"[ManifestKeyManager] ✗ 加载密钥失败: {e}")
            # 如果加载失败，生成新密钥
            self._generate_and_save_keys()
    
    def _ensure_peer_keys_dir(self):
        """确保节点公钥目录存在"""
        if not os.path.exists(self.peer_keys_dir):
            os.makedirs(self.peer_keys_dir)
            print(f"[ManifestKeyManager] ✓ 创建节点公钥目录: {self.peer_keys_dir}")
    
    def _get_peer_key_filename(self, node_id: str) -> str:
        """生成节点公钥文件的文件名（使用SHA256哈希确保安全）"""
        hash_obj = hashlib.sha256(node_id.encode('utf-8'))
        safe_node_id = hash_obj.hexdigest()[:16]
        return f"peer_key_{safe_node_id}.json"
    
    def _load_peer_keys(self):
        """加载已保存的节点公钥（扫描目录下的所有独立文件）"""
        print(f"[ManifestKeyManager] 加载节点公钥存储...")
        self.peer_keys_cache = {}
        
        try:
            if not os.path.exists(self.peer_keys_dir):
                self.peer_keys = {}
                print(f"[ManifestKeyManager] ✓ 节点公钥目录为空")
                return
            
            count = 0
            for filename in os.listdir(self.peer_keys_dir):
                if not filename.startswith('peer_key_') or not filename.endswith('.json'):
                    continue
                
                filepath = os.path.join(self.peer_keys_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    
                    node_id = data.get('node_id')
                    public_key_hex = data.get('public_key')
                    
                    if node_id and public_key_hex:
                        self.peer_keys_cache[node_id] = bytes.fromhex(public_key_hex)
                        count += 1
                except Exception as e:
                    print(f"[ManifestKeyManager] 加载文件 {filename} 失败: {e}")
            
            print(f"[ManifestKeyManager] ✓ 已加载 {count} 个节点公钥")
        except Exception as e:
            print(f"[ManifestKeyManager] ✗ 加载节点公钥失败: {e}")
            self.peer_keys_cache = {}
    
    def _save_peer_key_to_file(self, node_id: str, public_key: bytes):
        """保存单个节点的公钥到独立文件"""
        try:
            filename = self._get_peer_key_filename(node_id)
            filepath = os.path.join(self.peer_keys_dir, filename)
            
            data = {
                "node_id": node_id,
                "public_key": public_key.hex()
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            print(f"[ManifestKeyManager] ✗ 保存节点 {node_id} 公钥失败: {e}")
    
    def _load_peer_key_from_file(self, node_id: str) -> bytes:
        """从独立文件中加载指定节点的公钥"""
        try:
            filename = self._get_peer_key_filename(node_id)
            filepath = os.path.join(self.peer_keys_dir, filename)
            
            if not os.path.exists(filepath):
                return None
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            return bytes.fromhex(data.get('public_key', ''))
        except Exception as e:
            print(f"[ManifestKeyManager] ✗ 加载节点 {node_id} 公钥失败: {e}")
            return None
    
    def _delete_peer_key_file(self, node_id: str):
        """删除指定节点的公钥文件"""
        try:
            filename = self._get_peer_key_filename(node_id)
            filepath = os.path.join(self.peer_keys_dir, filename)
            
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            print(f"[ManifestKeyManager] ✗ 删除节点 {node_id} 公钥文件失败: {e}")
    
    def save_peer_public_key(self, node_id: str, public_key: bytes):
        """
        保存节点的清单公钥（每个节点单独保存为一个文件）
        
        Args:
            node_id: 节点身份指纹
            public_key: 节点的清单加密公钥
        """
        self.peer_keys_cache[node_id] = public_key
        self._save_peer_key_to_file(node_id, public_key)
        print(f"[ManifestKeyManager] ✓ 已保存节点 {node_id} 的公钥到独立文件")
    
    def get_peer_public_key(self, node_id: str) -> bytes:
        """
        获取指定节点的清单公钥
        
        Args:
            node_id: 节点身份指纹
        
        Returns:
            节点的清单加密公钥，如果不存在返回 None
        """
        if node_id in self.peer_keys_cache:
            return self.peer_keys_cache[node_id]
        
        public_key = self._load_peer_key_from_file(node_id)
        if public_key:
            self.peer_keys_cache[node_id] = public_key
        return public_key
    
    def remove_peer_public_key(self, node_id: str):
        """
        删除指定节点的清单公钥
        
        Args:
            node_id: 节点身份指纹
        """
        if node_id in self.peer_keys_cache:
            del self.peer_keys_cache[node_id]
        
        self._delete_peer_key_file(node_id)
    
    def list_peers(self) -> list:
        """获取所有已保存公钥的节点列表"""
        return list(self.peer_keys_cache.keys())
    
    def get_public_key(self) -> bytes:
        """获取公钥（用于分发给其他节点）"""
        return self.public_key
    
    def get_private_key(self) -> bytes:
        """获取私钥（用于解密清单）"""
        return self.private_key
    
    def encrypt_manifest(self, data: bytes, recipient_public_key: bytes) -> bytes:
        """
        使用接收者公钥加密清单
        
        Args:
            data: 清单数据
            recipient_public_key: 接收者的清单加密公钥
        
        Returns:
            加密后的清单数据
        """
        # 使用 Kyber KEM 封装密钥
        ciphertext, shared_secret = KyberKEM.encapsulate(recipient_public_key)
        
        # 使用共享密钥加密清单内容
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        
        # 打包：版本标识 + ciphertext + nonce + encrypted_data
        return b'\x03' + ciphertext + nonce + encrypted_data
    
    def decrypt_manifest(self, encrypted_data: bytes) -> bytes:
        """
        使用本地私钥解密清单
        
        Args:
            encrypted_data: 加密的清单数据
        
        Returns:
            解密后的清单数据
        """
        if len(encrypted_data) < 2:
            raise ValueError("Encrypted manifest is too short")
        
        # 检查版本
        version = encrypted_data[0:1]
        if version != b'\x03':
            raise ValueError(f"Unsupported manifest version: {version}")
        
        # 解析数据
        # ciphertext = 768 bytes (ML-KEM-512)
        # nonce = 12 bytes
        # encrypted_data = rest
        ciphertext = encrypted_data[1:769]
        nonce = encrypted_data[769:781]
        encrypted_manifest = encrypted_data[781:]
        
        # 使用私钥解封装共享密钥
        shared_secret = KyberKEM.decapsulate(ciphertext, self.private_key)
        
        # 使用共享密钥解密清单
        aesgcm = AESGCM(shared_secret)
        try:
            return aesgcm.decrypt(nonce, encrypted_manifest, None)
        except InvalidTag as e:
            raise InvalidTag("[ManifestKeyManager] 清单解密失败：密钥不匹配或数据损坏！") from e
    
    def destroy(self):
        """安全销毁密钥"""
        if self.private_key:
            self.private_key = b'\x00' * len(self.private_key)
        if self.public_key:
            self.public_key = b'\x00' * len(self.public_key)
        self.vault_password = b""
        import gc
        gc.collect()