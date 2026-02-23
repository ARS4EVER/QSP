"""
tests/test_signer_phase2.py
验证重构后的标准抗量子签名器 (DilithiumSigner)
测试签名和验签的基础业务逻辑。
"""
import unittest
import os
import sys

# 确保能正确导入 src 模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.crypto_lattice.wrapper import LatticeWrapper
from src.crypto_lattice.signer import DilithiumSigner

class TestDilithiumSigner(unittest.TestCase):
    
    def setUp(self):
        """测试前准备：生成一对标准的测试密钥"""
        self.pk, self.sk = LatticeWrapper.generate_signing_keypair()
        self.message = b"Test authentication message for reliable UDP handshake."

    def test_standard_sign_and_verify(self):
        """验证正常的签名与验签流程"""
        print("\n[Test] DilithiumSigner: Sign and Verify...")
        
        # 1. 签名
        signature = DilithiumSigner.sign(self.sk, self.message)
        
        # 确保签名返回的是字节流且符合 Dilithium2 的标准长度
        self.assertIsInstance(signature, bytes)
        self.assertEqual(len(signature), 2420, "Signature length must be exactly 2420 bytes for ML-DSA-44")
        
        # 2. 验签
        is_valid = DilithiumSigner.verify(self.pk, self.message, signature)
        
        self.assertTrue(is_valid, "Valid signature failed to verify.")
        print("  [Success] Standard signature correctly generated and verified.")

    def test_verify_failure_tampered_message(self):
        """验证被篡改的消息会被拒绝"""
        print("\n[Test] DilithiumSigner: Tampered Message Rejection...")
        
        signature = DilithiumSigner.sign(self.sk, self.message)
        tampered_msg = b"Tampered authentication message."
        
        is_valid = DilithiumSigner.verify(self.pk, tampered_msg, signature)
        
        self.assertFalse(is_valid, "Tampered message bypassed verification.")
        print("  [Success] Tampered message correctly rejected.")

    def test_verify_failure_wrong_key(self):
        """验证使用错误的公钥验签会被拒绝"""
        print("\n[Test] DilithiumSigner: Wrong Public Key Rejection...")
        
        signature = DilithiumSigner.sign(self.sk, self.message)
        
        # 生成一个不相关的恶意的（或错误的）公钥
        wrong_pk, _ = LatticeWrapper.generate_signing_keypair()
        
        is_valid = DilithiumSigner.verify(wrong_pk, self.message, signature)
        
        self.assertFalse(is_valid, "Signature verified with a wrong public key.")
        print("  [Success] Wrong public key correctly rejected.")

if __name__ == '__main__':
    unittest.main()
