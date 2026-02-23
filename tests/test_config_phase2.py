"""
tests/test_config_phase2.py
验证系统全局配置文件的正确性，确保旧的数学耦合已被清除。
"""
import unittest
import os
import sys

# 确保能正确导入 src 模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import src.config as config

class TestConfigPhase2(unittest.TestCase):

    def test_sig_params_cleaned(self):
        """验证签名参数仅保留网络常量，且正确清理了底层数学属性"""
        print("\n[Test] Config: Signature Parameters...")
        self.assertEqual(config.SigParams.NAME, "ML-DSA-44")
        self.assertEqual(config.SigParams.PK_SIZE, 1312)
        self.assertEqual(config.SigParams.SIG_SIZE, 2420)
        
        # 核心断言：确保 K, L, ETA 等旧 TSS 属性已不存在
        self.assertFalse(hasattr(config.SigParams, 'K'), "Mathematical constant K should be removed.")
        self.assertFalse(hasattr(config.SigParams, 'ETA'), "Mathematical constant ETA should be removed.")
        print("  [Success] Signature parameters are clean and correct.")

    def test_kem_params_correctness(self):
        """验证 Kyber512 的标准网络传输尺寸"""
        print("\n[Test] Config: KEM Parameters...")
        self.assertEqual(config.KEMParams.NAME, "ML-KEM-512")
        self.assertEqual(config.KEMParams.PK_SIZE, 800)
        self.assertEqual(config.KEMParams.CT_SIZE, 768)
        self.assertEqual(config.KEMParams.SS_SIZE, 32)
        print("  [Success] KEM parameters match ML-KEM-512 specifications.")

    def test_threshold_logic(self):
        """验证门限配置的数学逻辑合理性 (1 < t <= n)"""
        print("\n[Test] Config: Threshold Logic...")
        n = config.ThresholdParams.n_participants
        t = config.ThresholdParams.t
        
        self.assertGreater(t, 1, "Threshold must be strictly greater than 1 for meaningful sharing.")
        self.assertLessEqual(t, n, "Threshold 't' cannot exceed total participants 'n'.")
        print(f"  [Success] Threshold config valid: t={t}, n={n}.")

    def test_network_mtu_logic(self):
        """验证 MTU 配置与业务需求的逻辑关系"""
        print("\n[Test] Config: Network MTU...")
        # 确保预留了协议头空间
        self.assertLessEqual(config.NetworkParams.MTU, 1460, "MTU should be conservative (<=1460).")
        # 确保确实需要分片（业务逻辑自检）
        self.assertGreater(config.SigParams.SIG_SIZE, config.NetworkParams.MTU, 
                           "Signature size is larger than MTU. Splitting is required.")
        print("  [Success] Network MTU configuration is strictly bounded.")

if __name__ == '__main__':
    unittest.main()
