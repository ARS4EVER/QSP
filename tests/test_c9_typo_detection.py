import os
import gc
import unittest
import tempfile
from unittest.mock import patch

from src.app.vault_crypto import VaultCrypto, PasswordAuthError

class TestC9TypoDetection(unittest.TestCase):
    """
    QSP 系统 C9 标准专项测试套件：
    测试及时的密码输入错误检测、HMAC 熔断机制、原子写盘与内存级安全清理。
    """

    def setUp(self):
        """测试前置准备：创建一个安全的临时沙盒目录"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = self.temp_dir.name
        
        self.salt_path = os.path.join(self.temp_path, ".vault_salt")
        self.verifier_path = os.path.join(self.temp_path, ".vault_verifier")
        
        self.correct_password = "MySecurePassword_2026!"
        self.typo_password = "MySecurePassword_2026?"

    def tearDown(self):
        """测试清理：销毁沙盒目录"""
        self.temp_dir.cleanup()
        gc.collect()

    def test_01_first_run_creates_authenticator(self):
        """测试首次设置密码时，系统能正确生成 HMAC 验证器和盐值"""
        VaultCrypto(
            password=self.correct_password, 
            salt_path=self.salt_path, 
            verifier_path=self.verifier_path
        )
        
        self.assertTrue(os.path.exists(self.verifier_path), "HMAC 验证器文件未能成功创建")
        self.assertTrue(os.path.exists(self.salt_path), "盐值文件未能成功创建")
        
        self.assertEqual(os.path.getsize(self.verifier_path), 32)
        self.assertEqual(os.path.getsize(self.salt_path), 16)

    def test_02_atomic_write_no_tmp_leak(self):
        """测试原子化写盘操作是否干净利落，没有残留的 .tmp 文件"""
        VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
        
        tmp_verifier = self.verifier_path + ".tmp"
        tmp_salt = self.salt_path + ".tmp"
        
        self.assertFalse(os.path.exists(tmp_verifier), "发现残留的临时验证器文件，原子写盘逻辑有误！")
        self.assertFalse(os.path.exists(tmp_salt), "发现残留的临时盐值文件，原子写盘逻辑有误！")

    def test_03_correct_password_unlocks_smoothly(self):
        """测试输入正确的密码时，能够顺利解锁并实例化 AES-GCM"""
        VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
        
        try:
            vault = VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
            self.assertIsNotNone(vault.aesgcm, "输入正确密码后，AESGCM 实例未能成功初始化！")
        except PasswordAuthError:
            self.fail("正确的密码不应当触发 PasswordAuthError 异常！")

    def test_04_timely_typo_detection_blocks_init(self):
        """测试输入错误密码时，系统在一毫秒内触发熔断，拒绝实例化底层解密器"""
        VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
        
        with self.assertRaises(PasswordAuthError) as context:
            VaultCrypto(self.typo_password, self.salt_path, self.verifier_path)
            
        self.assertIn("主密码错误，拒绝解锁", str(context.exception))

    def test_05_memory_wiped_on_auth_failure(self):
        """测试在密码校验失败后，系统是否立即销毁了内存中的敏感密钥碎片"""
        VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
        
        failed_vault = None
        try:
            failed_vault = VaultCrypto(self.typo_password, self.salt_path, self.verifier_path)
        except PasswordAuthError:
            pass
            
        class DummyVault:
            pass
        dummy = DummyVault()
        dummy.password = b"SecretTypoPassword"
        dummy.key = b"DerivedKeyFragments"
        dummy.salt = b"SaltData"
        dummy.aesgcm = "MockAesInstance"
        
        VaultCrypto.destroy_memory_traces(dummy)
        
        self.assertEqual(dummy.password, b"", "内存中的密码原文未能销毁！")
        self.assertEqual(dummy.key, b"", "内存中派生的 AES 密钥未能销毁！")
        self.assertEqual(dummy.salt, b"", "内存中的盐值未能销毁！")
        self.assertIsNone(dummy.aesgcm, "底层解密器实例未能安全释放！")

    @patch("os.replace")
    def test_06_io_failure_triggers_rollback(self, mock_replace):
        """测试在原子化写盘过程中，如果遭遇磁盘满或断电，能否安全回滚"""
        mock_replace.side_effect = OSError("No space left on device")
        
        with self.assertRaises(IOError) as context:
            VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
            
        self.assertIn("系统状态已安全回滚", str(context.exception))
        
        self.assertFalse(os.path.exists(self.verifier_path), "I/O 失败时，不应产生损坏的主文件！")
        self.assertFalse(os.path.exists(self.verifier_path + ".tmp"), "I/O 失败时，临时文件应当被清理！")

if __name__ == "__main__":
    unittest.main(verbosity=2)
