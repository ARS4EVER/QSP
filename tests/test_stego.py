# -*- coding: utf-8 -*-
import os
import unittest
import numpy as np
import cv2
from src.image_stego.utils import ZigZagUtils, BitStreamUtils
from src.image_stego.dct_embed import DCTEmbedder
from src.image_stego.dct_extract import DCTExtractor
from src.image_stego.orchestrator import Module3Orchestrator

class TestStegoModule(unittest.TestCase):
    """
    测试隐写模块的单元测试类
    """
    
    def setUp(self):
        """
        测试前的准备工作
        """
        # 创建测试目录
        self.test_dir = "dataset/test_stego"
        os.makedirs(self.test_dir, exist_ok=True)
        
        # 创建测试载体图像（更大的尺寸，以容纳更多数据）
        self.test_carrier_path = os.path.join(self.test_dir, "test_carrier.png")
        self.test_carrier = np.zeros((256, 256, 3), dtype=np.uint8)
        cv2.imwrite(self.test_carrier_path, self.test_carrier)
        
        # 创建测试余数图像和倍数映射（更小的尺寸，以减少数据量）
        self.test_remainder = np.random.randint(0, 256, (4, 4, 3), dtype=np.uint8)
        self.test_multiple = np.random.randint(0, 10, (4, 4, 3), dtype=np.uint8)
        
        # 初始化测试对象
        self.zigzag_utils = ZigZagUtils()
        self.embedder = DCTEmbedder()
        self.extractor = DCTExtractor()
        self.orchestrator = Module3Orchestrator()
    
    def tearDown(self):
        """
        测试后的清理工作
        """
        # 清理测试文件
        if os.path.exists(self.test_carrier_path):
            os.remove(self.test_carrier_path)
        
        # 清理生成的含密图像
        for file in os.listdir(self.test_dir):
            if file.startswith('stego_'):
                os.remove(os.path.join(self.test_dir, file))
    
    def test_zigzag_scan(self):
        """
        测试Zigzag扫描工具
        """
        print("\n=== 测试Zigzag扫描工具 ===")
        
        # 测试索引0（DC系数）
        coords = self.zigzag_utils.get_coordinates(0)
        self.assertEqual(coords, (0, 0), "索引0应该对应(0, 0)")
        
        # 测试索引11（中频系数）
        coords = self.zigzag_utils.get_coordinates(11)
        self.assertEqual(coords, (3, 1), "索引11应该对应(3, 1)")
        
        # 测试索引12（中频系数）
        coords = self.zigzag_utils.get_coordinates(12)
        self.assertEqual(coords, (2, 2), "索引12应该对应(2, 2)")
        
        # 测试索引63（最后一个AC系数）
        coords = self.zigzag_utils.get_coordinates(63)
        self.assertEqual(coords, (7, 7), "索引63应该对应(7, 7)")
        
        print("✓ Zigzag扫描测试通过")
    
    def test_bitstream_utils(self):
        """
        测试位流处理工具
        """
        print("\n=== 测试位流处理工具 ===")
        
        # 测试字节转比特
        test_bytes = b'\x01\x02'
        bits = BitStreamUtils.bytes_to_bits(test_bytes)
        self.assertEqual(len(bits), 16, "2字节应该转换为16比特")
        
        # 测试比特转字节
        reconstructed_bytes = BitStreamUtils.bits_to_bytes(bits)
        self.assertEqual(reconstructed_bytes, test_bytes, "重构的字节应该与原始字节一致")
        
        # 测试整数转字节
        test_int = 123456789
        int_bytes = BitStreamUtils.int_to_bytes(test_int)
        reconstructed_int = BitStreamUtils.bytes_to_int(int_bytes)
        self.assertEqual(reconstructed_int, test_int, "重构的整数应该与原始整数一致")
        
        print("✓ 位流处理测试通过")
    
    def test_dct_embed_extract(self):
        """
        测试DCT嵌入器和提取器
        """
        print("\n=== 测试DCT嵌入器和提取器 ===")
        
        # 创建测试载体图像
        carrier = np.zeros((128, 128, 3), dtype=np.uint8)
        
        # 创建测试数据
        test_data = b"Test secret data for steganography"
        
        # 嵌入数据
        stego = self.embedder.embed(carrier, test_data)
        
        # 提取数据
        extracted_data = self.extractor.extract(stego)
        
        # 验证提取的数据与原始数据一致
        self.assertEqual(extracted_data, test_data, "提取的数据应该与原始数据一致")
        
        print("✓ DCT嵌入和提取测试通过")
    
    def test_orchestrator(self):
        """
        测试模块三编排器
        """
        print("\n=== 测试模块三编排器 ===")
        
        # 1. 执行嵌入流程
        stego_img = self.orchestrator.process_step_3_embedding(
            self.test_carrier_path, 
            self.test_remainder, 
            self.test_multiple
        )
        
        # 2. 保存含密图像
        stego_path = os.path.join(self.test_dir, "stego_test.png")
        cv2.imwrite(stego_path, stego_img)
        
        # 3. 执行提取流程
        recovered_remainder, recovered_multiple = self.orchestrator.process_step_3_extraction(stego_path)
        
        # 4. 验证提取的数据与原始数据一致
        np.testing.assert_array_equal(recovered_remainder, self.test_remainder, "提取的余数图像应该与原始余数图像一致")
        np.testing.assert_array_equal(recovered_multiple, self.test_multiple, "提取的倍数映射应该与原始倍数映射一致")
        
        print("✓ 模块三编排器测试通过")
    
    def test_capacity_check(self):
        """
        测试容量检查功能
        """
        print("\n=== 测试容量检查功能 ===")
        
        # 创建小尺寸载体图像
        small_carrier = np.zeros((32, 32, 3), dtype=np.uint8)
        
        # 创建超出容量的数据
        large_data = b"x" * 1000  # 1000字节，远超出32x32图像的容量
        
        # 验证是否抛出容量不足的异常
        with self.assertRaises(ValueError):
            self.embedder.embed(small_carrier, large_data)
        
        print("✓ 容量检查测试通过")

if __name__ == "__main__":
    # 运行所有测试
    unittest.main()
