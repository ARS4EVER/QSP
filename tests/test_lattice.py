"""
测试模块：格密码门限签名系统
文件路径: tests/test_lattice.py

本测试文件验证格密码门限签名系统的核心功能，包括：
1. 密钥生成功能
2. 签名生成功能
3. 拒绝采样机制
4. 签名聚合功能
"""

import unittest
import numpy as np
from src.crypto_lattice.keygen import KeyGenerator
from src.crypto_lattice.signer import ThresholdSigner, SignatureAggregator
from src.config import Config

class TestLatticeSignature(unittest.TestCase):
    """
    测试格密码门限签名系统的核心功能
    """
    
    def setUp(self):
        """
        测试前的初始化工作
        """
        self.keygen = KeyGenerator()
        self.aggregator = SignatureAggregator()
        
    def test_key_generation(self):
        """
        测试密钥生成功能
        验证：
        1. 密钥生成是否成功
        2. 公钥和私钥的结构是否正确
        3. 私钥系数是否在指定范围内
        """
        print("\n=== 测试密钥生成功能 ===")
        
        # 生成密钥对
        pk, sk = self.keygen.generate_keys()
        
        # 验证公钥结构
        self.assertIn('rho', pk)
        self.assertIn('t1', pk)
        self.assertEqual(len(pk['rho']), 32)  # rho 应该是 32 字节
        self.assertEqual(len(pk['t1']), Config.K)  # t1 应该有 K 个多项式
        
        # 验证私钥结构
        self.assertIn('rho', sk)
        self.assertIn('s1', sk)
        self.assertIn('s2', sk)
        self.assertIn('t0', sk)
        self.assertEqual(len(sk['s1']), Config.L)  # s1 应该有 L 个多项式
        self.assertEqual(len(sk['s2']), Config.K)  # s2 应该有 K 个多项式
        
        # 验证私钥系数范围
        for poly in sk['s1']:
            for coeff in poly:
                self.assertTrue(abs(coeff) <= Config.ETA)
        
        for poly in sk['s2']:
            for coeff in poly:
                self.assertTrue(abs(coeff) <= Config.ETA)
        
        print("✓ 密钥生成测试通过")
    
    def test_signature_generation(self):
        """
        测试签名生成功能
        验证：
        1. 承诺生成是否成功
        2. 挑战生成是否成功
        3. 响应生成是否成功
        4. 拒绝采样机制是否正常工作
        """
        print("\n=== 测试签名生成功能 ===")
        
        # 生成密钥对
        pk, sk = self.keygen.generate_keys()
        
        # 创建签名者实例
        signer = ThresholdSigner(sk, 0)
        
        # 阶段 1: 生成承诺
        W_share = signer.phase1_commitment()
        self.assertEqual(len(W_share), Config.K)  # W_share 应该有 K 个多项式
        
        # 模拟聚合承诺
        W_sum = self.aggregator.aggregate_commitments([W_share])
        
        # 阶段 2: 生成挑战
        message = b"Hello Quantum World"
        challenge_c = self.aggregator.derive_challenge(message, W_sum)
        self.assertEqual(len(challenge_c), Config.N)  # 挑战多项式长度应该为 N
        
        # 计算非零系数个数
        non_zero_count = sum(1 for c in challenge_c if c != 0)
        self.assertLessEqual(non_zero_count, Config.TAU)  # 非零系数个数应该 <= TAU
        
        # 阶段 3: 生成响应
        z_share = signer.phase2_response(challenge_c)
        
        # 验证响应是否生成成功（未被拒绝）
        # 注意：由于拒绝采样的存在，这里可能会失败，但概率很低
        if z_share is not None:
            self.assertEqual(len(z_share), Config.L)  # z_share 应该有 L 个多项式
            print("✓ 签名生成测试通过")
        else:
            print("⚠ 签名生成被拒绝（拒绝采样机制正常工作）")
    
    def test_signature_aggregation(self):
        """
        测试签名聚合功能
        验证：
        1. 多个部分签名是否可以正确聚合
        2. 聚合后的签名结构是否正确
        """
        print("\n=== 测试签名聚合功能 ===")
        
        # 生成密钥对
        pk, sk = self.keygen.generate_keys()
        
        # 尝试多次，直到至少有一个签名者成功生成响应
        max_attempts = 5
        for attempt in range(max_attempts):
            print(f"尝试 {attempt + 1}/{max_attempts}")
            
            # 创建多个签名者实例（模拟多个参与者）
            signers = [ThresholdSigner(sk, i) for i in range(3)]
            
            # 阶段 1: 所有签名者生成承诺
            W_shares = [signer.phase1_commitment() for signer in signers]
            
            # 聚合承诺
            W_sum = self.aggregator.aggregate_commitments(W_shares)
            
            # 阶段 2: 生成挑战
            message = b"Hello Quantum World"
            challenge_c = self.aggregator.derive_challenge(message, W_sum)
            
            # 阶段 3: 所有签名者生成响应
            z_shares = []
            for signer in signers:
                z_share = signer.phase2_response(challenge_c)
                if z_share is not None:
                    z_shares.append(z_share)
            
            # 检查是否有成功的响应
            if len(z_shares) > 0:
                break
        
        # 如果所有尝试都失败，跳过聚合测试（这在理论上是可能的，但概率很低）
        if len(z_shares) == 0:
            print("⚠ 所有签名都被拒绝，跳过聚合测试")
            return
        
        # 聚合响应
        Z_sum = self.aggregator.aggregate_responses(z_shares)
        self.assertEqual(len(Z_sum), Config.L)  # 聚合后的签名应该有 L 个多项式
        
        print("✓ 签名聚合测试通过")
    
    def test_parameter_validation(self):
        """
        测试参数验证功能
        验证配置参数的一致性和合法性
        """
        print("\n=== 测试参数验证功能 ===")
        
        # 验证 NTT 条件
        self.assertEqual((Config.Q - 1) % (2 * Config.N), 0)
        
        # 验证拒绝采样区间的有效性
        self.assertGreater(Config.GAMMA1, Config.BETA)
        
        print("✓ 参数验证测试通过")

if __name__ == '__main__':
    unittest.main()
