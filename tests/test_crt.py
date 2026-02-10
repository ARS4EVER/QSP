# -*- coding: utf-8 -*-
import os
import unittest
import numpy as np
from PIL import Image

from src.config import Config
from src.secret_sharing.splitter import ImageCRTSplitter
from src.secret_sharing.reconstructor import ImageCRTReconstructor

class TestCRTSecretSharing(unittest.TestCase):
    """
    测试CRT秘密共享模块的单元测试类
    """
    
    def setUp(self):
        """
        测试前的准备工作
        """
        # 创建测试目录
        self.test_dir = "dataset/test_crt"
        os.makedirs(self.test_dir, exist_ok=True)
        
        # 创建测试图像
        self.test_img_path = os.path.join(self.test_dir, "test_secret.png")
        self.test_img = Image.new('RGB', (64, 64), color='red')
        self.test_img.save(self.test_img_path)
        
        # 创建模拟格签名
        self.test_signature = b'test_signature_1234567890'
        
        # 初始化分割器和重构器
        self.splitter = ImageCRTSplitter()
        self.reconstructor = ImageCRTReconstructor()
    
    def tearDown(self):
        """
        测试后的清理工作
        """
        # 清理测试文件
        if os.path.exists(self.test_img_path):
            os.remove(self.test_img_path)
        
        # 清理生成的份额文件
        for file in os.listdir(self.test_dir):
            if file.startswith('share_') or file.startswith('visual_shadow_'):
                os.remove(os.path.join(self.test_dir, file))
    
    def test_image_split(self):
        """
        测试图像分割功能
        """
        print("\n=== 测试图像分割功能 ===")
        
        # 执行分割
        share_paths = self.splitter.split_image(
            self.test_img_path, 
            signature_data=self.test_signature, 
            output_dir=self.test_dir
        )
        
        # 验证分割结果
        self.assertEqual(len(share_paths), Config.N_PARTICIPANTS, f"应该生成 {Config.N_PARTICIPANTS} 个份额")
        
        # 验证份额文件存在
        for path in share_paths:
            self.assertTrue(os.path.exists(path), f"份额文件 {path} 不存在")
        
        print("✓ 图像分割测试通过")
    
    def test_image_reconstruction(self):
        """
        测试图像重构功能
        """
        print("\n=== 测试图像重构功能 ===")
        
        # 1. 先执行分割
        share_paths = self.splitter.split_image(
            self.test_img_path, 
            signature_data=self.test_signature, 
            output_dir=self.test_dir
        )
        
        # 2. 验证份额数量
        self.assertGreaterEqual(len(share_paths), Config.T_THRESHOLD, f"份额数量不足 {Config.T_THRESHOLD}")
        
        # 3. 随机选择 T 个份额进行重构
        import random
        selected_shares = random.sample(share_paths, Config.T_THRESHOLD)
        
        # 4. 执行重构
        recovered_img, recovered_sig = self.reconstructor.reconstruct_image(selected_shares)
        
        # 5. 验证重构结果
        self.assertIsNotNone(recovered_img, "重构图像不应为 None")
        self.assertEqual(recovered_sig, self.test_signature, "重构签名与原始签名不匹配")
        
        print("✓ 图像重构测试通过")
    
    def test_threshold_validation(self):
        """
        测试门限验证功能
        """
        print("\n=== 测试门限验证功能 ===")
        
        # 1. 先执行分割
        share_paths = self.splitter.split_image(
            self.test_img_path, 
            signature_data=self.test_signature, 
            output_dir=self.test_dir
        )
        
        # 2. 尝试使用少于 T 个份额进行重构
        with self.assertRaises(ValueError):
            # 选择 T-1 个份额
            insufficient_shares = share_paths[:Config.T_THRESHOLD-1]
            self.reconstructor.reconstruct_image(insufficient_shares)
        
        print("✓ 门限验证测试通过")
    
    def test_modulus_validation(self):
        """
        测试模数验证功能
        """
        print("\n=== 测试模数验证功能 ===")
        
        # 1. 先执行分割
        share_paths = self.splitter.split_image(
            self.test_img_path, 
            signature_data=self.test_signature, 
            output_dir=self.test_dir
        )
        
        # 2. 验证份额文件中的模数与配置一致
        for path in share_paths:
            packet = np.load(path, allow_pickle=True).item()
            idx = packet['index']
            expected_mod = Config.MODULI[idx]
            actual_mod = packet['modulus']
            self.assertEqual(expected_mod, actual_mod, f"模数不匹配: 期望 {expected_mod}, 实际 {actual_mod}")
        
        print("✓ 模数验证测试通过")
    
    def test_signature_integration(self):
        """
        测试格签名集成功能
        """
        print("\n=== 测试格签名集成功能 ===")
        
        # 1. 生成不同的测试签名
        test_signatures = [
            b'signature_1',
            b'signature_2',
            b'signature_3'
        ]
        
        for sig in test_signatures:
            # 2. 执行分割
            share_paths = self.splitter.split_image(
                self.test_img_path, 
                signature_data=sig, 
                output_dir=self.test_dir
            )
            
            # 3. 执行重构
            selected_shares = share_paths[:Config.T_THRESHOLD]
            recovered_img, recovered_sig = self.reconstructor.reconstruct_image(selected_shares)
            
            # 4. 验证签名
            self.assertEqual(recovered_sig, sig, f"签名不匹配: 期望 {sig}, 实际 {recovered_sig}")
        
        print("✓ 格签名集成测试通过")
    
    def test_image_quality(self):
        """
        测试图像质量（确保重构后的图像与原始图像相似）
        """
        print("\n=== 测试图像质量 ===")
        
        # 1. 创建一个更复杂的测试图像
        complex_img = Image.new('RGB', (64, 64))
        for i in range(64):
            for j in range(64):
                complex_img.putpixel((i, j), (i % 256, j % 256, (i+j) % 256))
        complex_img_path = os.path.join(self.test_dir, "complex_test.png")
        complex_img.save(complex_img_path)
        
        # 2. 执行分割
        share_paths = self.splitter.split_image(
            complex_img_path, 
            signature_data=self.test_signature, 
            output_dir=self.test_dir
        )
        
        # 3. 执行重构
        selected_shares = share_paths[:Config.T_THRESHOLD]
        recovered_img, _ = self.reconstructor.reconstruct_image(selected_shares)
        
        # 4. 验证图像大小
        self.assertEqual(recovered_img.size, complex_img.size, "重构图像大小与原始图像不匹配")
        
        # 5. 验证图像模式
        self.assertEqual(recovered_img.mode, complex_img.mode, "重构图像模式与原始图像不匹配")
        
        # 6. 清理
        if os.path.exists(complex_img_path):
            os.remove(complex_img_path)
        
        print("✓ 图像质量测试通过")

if __name__ == "__main__":
    # 运行所有测试
    unittest.main()
