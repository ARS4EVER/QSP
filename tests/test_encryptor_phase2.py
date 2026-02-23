"""
tests/test_encryptor_phase2.py
[测试] Kyber KEM 密钥协商流程
"""
import unittest
import os
import sys

# 路径设置：确保能导入 src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.crypto_lattice.encryptor import KyberKEM
from src.config import KEMParams

class TestKyberKEM(unittest.TestCase):
    
    def test_kem_negotiation_flow(self):
        """测试完整的密钥协商流程 (Alice <-> Bob)"""
        print("\n[Test] Starting Kyber KEM Negotiation...")
        
        # 1. [Alice] 生成密钥对 (模拟服务端)
        print("  1. Alice generates keypair...")
        alice_pk, alice_sk = KyberKEM.generate_keypair()
        
        # 验证尺寸 (Kyber512 标准)
        self.assertEqual(len(alice_pk), KEMParams.PK_SIZE, f"PK size should be {KEMParams.PK_SIZE}")
        # 私钥大小通常是 1632 (d + z + pk) 或 2400 (depend on implementation), kyber-py 通常是 1632
        self.assertGreater(len(alice_sk), 0)
        
        # 2. [Bob] 封装 (模拟客户端)
        # Bob 拿到 Alice 的公钥，生成共享密钥
        print("  2. Bob encapsulates shared secret...")
        ciphertext, bob_ss = KyberKEM.encapsulate(alice_pk)
        
        # 验证密文尺寸
        self.assertEqual(len(ciphertext), KEMParams.CT_SIZE, f"Ciphertext size should be {KEMParams.CT_SIZE}")
        # 验证共享密钥尺寸 (32 bytes / 256 bits)
        self.assertEqual(len(bob_ss), KEMParams.SS_SIZE)
        
        # 3. [Alice] 解封装
        # Alice 收到密文，使用私钥还原共享密钥
        print("  3. Alice decapsulates ciphertext...")
        alice_ss = KyberKEM.decapsulate(ciphertext, alice_sk)
        
        # 4. [Verification] 对比双方密钥
        print(f"  Bob's Secret:   {bob_ss.hex()[:16]}...")
        print(f"  Alice's Secret: {alice_ss.hex()[:16]}...")
        
        self.assertEqual(bob_ss, alice_ss, "CRITICAL: Shared secrets do not match!")
        print("  [Success] Shared secrets match perfectly.")

    def test_invalid_decapsulation(self):
        """测试隐式拒绝 - 给定错误密文"""
        print("\n[Test] Testing Implicit Rejection (Security Check)...")
        pk, sk = KyberKEM.generate_keypair()
        
        # 构造一个随机的"坏"密文
        bad_ciphertext = os.urandom(KEMParams.CT_SIZE)
        
        # 尝试解封装
        # Kyber 标准规定：如果密文无效，不抛异常，而是返回一个伪随机密钥
        # 这样攻击者无法通过"报错/不报错"来推断私钥信息 (CCA Secure)
        ss_fake = KyberKEM.decapsulate(bad_ciphertext, sk)
        
        self.assertEqual(len(ss_fake), KEMParams.SS_SIZE)
        print("  [Success] Decapsulation returned pseudorandom key for bad ciphertext.")

if __name__ == '__main__':
    unittest.main()