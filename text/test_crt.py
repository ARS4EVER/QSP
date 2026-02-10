# -*- coding: utf-8 -*-
"""
测试CRT秘密共享模块
"""
import os
import sys
import numpy as np
from PIL import Image

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.secret_sharing.splitter import ImageCRTSplitter
from src.secret_sharing.reconstructor import ImageCRTReconstructor
from src.secret_sharing.moduli_gen import generate_secure_moduli
from src.config import Config

def test_crt_sharing():
    """测试CRT秘密共享功能"""
    print("=== 测试CRT秘密共享功能 ===")
    
    # 创建测试图像
    test_img_path = "dataset/test_crt.png"
    if not os.path.exists(test_img_path):
        os.makedirs("dataset", exist_ok=True)
        # 创建一个简单的测试图像，包含不同颜色的方块
        test_img = np.zeros((64, 64, 3), dtype=np.uint8)
        test_img[10:20, 10:20] = [255, 0, 0]   # 红色方块
        test_img[30:40, 30:40] = [0, 255, 0]   # 绿色方块
        test_img[50:60, 50:60] = [0, 0, 255]   # 蓝色方块
        Image.fromarray(test_img).save(test_img_path)
        print(f"创建测试图像: {test_img_path}")
    
    # 初始化分割器
    n = 5
    t = 3
    moduli = generate_secure_moduli(n, t)
    splitter = ImageCRTSplitter(n, t, moduli)
    
    # 执行分割
    print("\n执行图像分割...")
    share_paths = splitter.split_image(test_img_path)
    print(f"生成了 {len(share_paths)} 个份额")
    
    # 初始化重构器
    reconstructor = ImageCRTReconstructor()
    
    # 执行重构
    print("\n执行图像重构...")
    # 使用所有份额进行重构
    reconstructed_img, signature = reconstructor.reconstruct_image(share_paths)
    
    # 保存重构后的图像
    reconstructed_path = "dataset/reconstructed_crt.png"
    reconstructed_img.save(reconstructed_path)
    print(f"重构后的图像已保存: {reconstructed_path}")
    
    # 验证重构结果
    print("\n验证重构结果...")
    original_img = Image.open(test_img_path)
    original_array = np.array(original_img)
    reconstructed_array = np.array(reconstructed_img)
    
    # 计算差异
    diff = np.abs(original_array - reconstructed_array)
    max_diff = np.max(diff)
    mean_diff = np.mean(diff)
    
    print(f"最大像素差异: {max_diff}")
    print(f"平均像素差异: {mean_diff:.4f}")
    
    if max_diff == 0:
        print("✅ 测试通过：重构后的图像与原始图像完全相同！")
    else:
        print("❌ 测试失败：重构后的图像与原始图像存在差异！")
    
    return max_diff == 0

if __name__ == "__main__":
    test_crt_sharing()
