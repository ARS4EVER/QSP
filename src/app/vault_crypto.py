"""
src/app/vault_crypto.py
[Phase 10] 本地金库加密模块 (Vault Crypto)
保护落盘的 Shamir 份额，引入 PBKDF2 密钥派生与 AES-GCM，防止物理设备被攻破时泄露资产。
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class VaultCrypto:
    def __init__(self, password: str, vault_dir: str = "./vault"):
        """
        初始化金库锁。使用统一的主密码派生高强度 AES 密钥。
        """
        self.vault_dir = vault_dir
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)
            
        self.salt_path = os.path.join(self.vault_dir, ".vault_salt")
        self.key = self._derive_key(password)
        self.aes_gcm = AESGCM(self.key)

    def _derive_key(self, password: str) -> bytes:
        """从用户密码中利用 PBKDF2 算法加上强随机盐提取出 256位 密钥"""
        if os.path.exists(self.salt_path):
            with open(self.salt_path, "rb") as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_path, "wb") as f:
                f.write(salt)

        # 迭代十万次，显著增加暴力破解成本
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt_chunk(self, plaintext: bytes) -> bytes:
        """对 512 字节块进行 GCM 认证加密 (附加 12字节 Nonce 和 16字节 Tag)"""
        nonce = os.urandom(12)
        return nonce + self.aes_gcm.encrypt(nonce, plaintext, None)

    def decrypt_chunk(self, ciphertext: bytes) -> bytes:
        """实时解密并校验磁盘读取的块是否遭到本地篡改"""
        nonce = ciphertext[:12]
        payload = ciphertext[12:]
        return self.aes_gcm.decrypt(nonce, payload, None)
