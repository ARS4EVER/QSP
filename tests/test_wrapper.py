"""
tests/test_wrapper.py
验证重构后的标准黑盒密码学接口 (ML-DSA & ML-KEM)
这里只关心签名能否验过、密钥能否交换成功，不再关心底层的多项式细节。
"""
import unittest
import os
import sys

# 确保能正确导入 src 模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.crypto_lattice.wrapper import LatticeWrapper

class TestLatticeWrapper(unittest.TestCase):

    # ---------------------------------------------------------
    # ML-DSA (Dilithium) 测试组
    # ---------------------------------------------------------

    def test_ml_dsa_sign_verify_success(self):
        """[Dilithium] 验证正常的签名与验签流程"""
        print("\n[Test] ML-DSA Sign/Verify Success...")
        pk, sk = LatticeWrapper.generate_signing_keypair()
        message = b"Secure RUDP handhake message"
        
        signature = LatticeWrapper.sign_message(sk, message)
        
        # 验证 Dilithium2 标准签名长度
        self.assertEqual(len(signature), 2420, "Dilithium2 signature length should be 2420 bytes")
        
        is_valid = LatticeWrapper.verify_signature(pk, message, signature)
        self.assertTrue(is_valid, "Valid signature should be verified successfully")
        print("  [Success] ML-DSA signature generated and verified.")

    def test_ml_dsa_verify_failure_wrong_message(self):
        """[Dilithium] 验证被篡改的消息会导致验签失败"""
        print("\n[Test] ML-DSA Verify Failure (Wrong Message)...")
        pk, sk = LatticeWrapper.generate_signing_keypair()
        message = b"Original message"
        tampered_message = b"Tampered message"
        
        signature = LatticeWrapper.sign_message(sk, message)
        
        is_valid = LatticeWrapper.verify_signature(pk, tampered_message, signature)
        self.assertFalse(is_valid, "Tampered message should fail verification")
        print("  [Success] Tampered message correctly rejected.")

    def test_ml_dsa_verify_failure_wrong_signature(self):
        """[Dilithium] 验证损坏的签名会导致验签失败"""
        print("\n[Test] ML-DSA Verify Failure (Wrong Signature)...")
        pk, sk = LatticeWrapper.generate_signing_keypair()
        message = b"Original message"
        
        signature = LatticeWrapper.sign_message(sk, message)
        
        # 破坏签名的第一个字节来模拟传输错误或伪造
        bad_signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
        
        is_valid = LatticeWrapper.verify_signature(pk, message, bad_signature)
        self.assertFalse(is_valid, "Corrupted signature should fail verification")
        print("  [Success] Corrupted signature correctly rejected.")

    # ---------------------------------------------------------
    # ML-KEM (Kyber) 测试组
    # ---------------------------------------------------------

    def test_ml_kem_encaps_decaps_success(self):
        """[Kyber] 验证正常的密钥封装与解封装流程"""
        print("\n[Test] ML-KEM Encaps/Decaps Success...")
        pk, sk = LatticeWrapper.kem_keygen()
        
        # Client 使用 Server 的 pk 进行封装
        ciphertext, shared_secret_client = LatticeWrapper.kem_encapsulate(pk)
        
        # 验证 Kyber512 的标准输出长度
        self.assertEqual(len(ciphertext), 768, "Kyber512 ciphertext should be 768 bytes")
        self.assertEqual(len(shared_secret_client), 32, "Kyber512 shared secret should be 32 bytes")
        
        # Server 使用自己的 sk 进行解封装
        shared_secret_server = LatticeWrapper.kem_decapsulate(sk, ciphertext)
        
        # 双方得到的对称密钥必须一致
        self.assertEqual(shared_secret_client, shared_secret_server, "Shared secrets must match")
        print("  [Success] ML-KEM shared secrets matched.")

    def test_ml_kem_decaps_failure_wrong_sk(self):
        """[Kyber] 验证使用错误的私钥解封装会触发隐式拒绝机制"""
        print("\n[Test] ML-KEM Decaps Failure (Wrong SK)...")
        pk1, sk1 = LatticeWrapper.kem_keygen()
        pk2, sk2 = LatticeWrapper.kem_keygen() # 另一个完全无关的密钥对
        
        ciphertext, shared_secret_client = LatticeWrapper.kem_encapsulate(pk1)
        
        # 攻击者尝试用错误的私钥 sk2 解封装密文
        # Kyber 的特性：解密失败不会报错，而是返回一个伪随机密钥（Implicit Rejection）
        shared_secret_wrong = LatticeWrapper.kem_decapsulate(sk2, ciphertext)
        
        # 两个密钥必须不同（隐式拒绝）
        self.assertNotEqual(shared_secret_client, shared_secret_wrong, 
                           "Wrong SK should yield a completely different pseudo-random secret")
        print("  [Success] ML-KEM correctly implemented implicit rejection (secrets do not match).")


if __name__ == '__main__':
    unittest.main()
