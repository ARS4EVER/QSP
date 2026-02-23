"""
tests/test_vault_encryption_phase10.py
测试本地 Vault 的 PBKDF2 密码派生一致性与 AES-GCM 块级透明加解密。
"""
import unittest
import os
import tempfile
import shutil
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.app.vault_crypto import VaultCrypto

class TestVaultEncryption(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_key_derivation_consistency(self):
        """测试：相同的密码与持久化的 Salt，必须稳定派生出完全一致的 256 位 AES 密钥"""
        # 第一次初始化，会随机生成 salt 并落盘
        crypto1 = VaultCrypto("Super_Secret_Password_123!", self.test_dir)
        key1 = crypto1.key
        
        self.assertEqual(len(key1), 32)  # SHA256 派生应为 32 字节 (256位)
        
        # 模拟重启软件，第二次初始化，必须读取现存的 salt
        crypto2 = VaultCrypto("Super_Secret_Password_123!", self.test_dir)
        key2 = crypto2.key
        
        self.assertEqual(key1, key2, "读取磁盘存在的 Salt 派生 Key 失败！")

    def test_chunk_encryption_and_decryption(self):
        """测试：512字节块被透明加密后必须发生正确的长度膨胀，且能无损解密"""
        crypto = VaultCrypto("My_Vault_Key", self.test_dir)
        
        # 伪造一个 512 字节的 Shamir 切片
        original_chunk = b"A" * 512
        
        # 加密并写入假想的磁盘
        encrypted_chunk = crypto.encrypt_chunk(original_chunk)
        
        # 验证长度膨胀：512 + 12 (Nonce) + 16 (Tag) = 540
        self.assertEqual(len(encrypted_chunk), 540, "密文块长度未发生符合 AES-GCM 规范的膨胀")
        self.assertNotEqual(original_chunk, encrypted_chunk[:512], "数据未发生实质混淆！")
        
        # 从磁盘读出并解密
        decrypted_chunk = crypto.decrypt_chunk(encrypted_chunk)
        self.assertEqual(original_chunk, decrypted_chunk, "解密后的数据受损，不等于原始输入")

    def test_tamper_detection(self):
        """测试：AES-GCM 认证加密能否成功拦截磁盘级别的恶意篡改"""
        crypto = VaultCrypto("My_Vault_Key", self.test_dir)
        original_chunk = os.urandom(512)
        
        encrypted_chunk = bytearray(crypto.encrypt_chunk(original_chunk))
        
        # 模拟勒索软件或黑客恶意修改了本地 .dat 文件中的一个字节
        encrypted_chunk[100] ^= 0xFF
        
        from cryptography.exceptions import InvalidTag
        with self.assertRaises(InvalidTag, msg="AES-GCM 未能有效拦截磁盘级篡改！"):
            crypto.decrypt_chunk(bytes(encrypted_chunk))

if __name__ == "__main__":
    unittest.main()
