#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 QSP 阶段三功能
"""

import os
import sys
import json
import hashlib
from PIL import Image

# 添加QSP目录到Python路径，这样可以使用src包
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.image_stego.dct_extract import DCTExtractor
from src.crypto_lattice.signer import LatticeSigner
from src.secret_sharing.reconstructor import ImageCRTReconstructor

print("===========================================")
print("   🧪 QSP 阶段三功能测试")
print("===========================================")

# 测试1: DCTExtractor 基本功能
print("\n1. 测试 DCTExtractor 基本功能...")
try:
    extractor = DCTExtractor()
    print("   ✅ DCTExtractor 初始化成功")
    
    # 测试提取功能 (使用测试图像)
    test_image = "dataset/carrier.png"
    if os.path.exists(test_image):
        data = extractor.extract(test_image)
        print(f"   ✅ 从图像中提取数据成功 (大小: {len(data)} bytes)")
    else:
        print(f"   ⚠️  测试图像不存在: {test_image}")
except Exception as e:
    print(f"   ❌ DCTExtractor 测试失败: {e}")

# 测试2: LatticeSigner 基本功能
print("\n2. 测试 LatticeSigner 基本功能...")
try:
    signer = LatticeSigner()
    print("   ✅ LatticeSigner 初始化成功")
    
    # 测试签名和验证功能 (需要密钥对)
    test_sk_path = "data/keys/user_1770640149.sk"
    test_pk_path = "data/keys/user_1770640149.pk"
    
    if os.path.exists(test_sk_path) and os.path.exists(test_pk_path):
        with open(test_sk_path, 'r') as f:
            sk = json.load(f)
        with open(test_pk_path, 'r') as f:
            pk = json.load(f)
        
        # 测试消息
        test_message = b"test message for lattice signature"
        
        # 生成签名
        signature = signer.sign(sk, test_message)
        print("   ✅ 签名生成成功")
        
        # 验证签名
        isValid = signer.verify(pk, test_message, signature)
        if isValid:
            print("   ✅ 签名验证成功")
        else:
            print("   ❌ 签名验证失败")
    else:
        print("   ⚠️  测试密钥对不存在，跳过签名验证测试")
except Exception as e:
    print(f"   ❌ LatticeSigner 测试失败: {e}")

# 测试3: ImageCRTReconstructor 基本功能
print("\n3. 测试 ImageCRTReconstructor 基本功能...")
try:
    reconstructor = ImageCRTReconstructor()
    print("   ✅ ImageCRTReconstructor 初始化成功")
    
    # 测试反序列化功能
    test_data = b"test serialization data"
    result = reconstructor.deserialize_share(test_data)
    print(f"   ✅ 反序列化功能测试成功 (结果: {result})")
    
    # 测试重构功能 (需要份额文件)
    test_shares = ["data/shares/share_1_m257.npy", "data/shares/share_2_m263.npy", "data/shares/share_3_m269.npy"]
    valid_shares = [path for path in test_shares if os.path.exists(path)]
    
    if len(valid_shares) >= 3:
        img, sig = reconstructor.reconstruct_image(valid_shares)
        print("   ✅ 图像重构功能测试成功")
        if sig:
            print(f"   ✅ 从份额中提取签名成功 (长度: {len(sig)} bytes)")
    else:
        print("   ⚠️  测试份额文件不足，跳过重构测试")
except Exception as e:
    print(f"   ❌ ImageCRTReconstructor 测试失败: {e}")

# 测试4: unlock_asset.py 基本功能
print("\n4. 测试 unlock_asset.py 基本功能...")
try:
    # 检查文件是否存在
    unlock_script = "unlock_asset.py"
    if os.path.exists(unlock_script):
        print("   ✅ unlock_asset.py 文件存在")
        
        # 检查文件内容
        with open(unlock_script, 'r') as f:
            content = f.read()
        
        if "DCTExtractor" in content and "LatticeSigner" in content and "ImageCRTReconstructor" in content:
            print("   ✅ unlock_asset.py 正确导入了所需模块")
        else:
            print("   ❌ unlock_asset.py 缺少必要的模块导入")
    else:
        print(f"   ❌ unlock_asset.py 文件不存在")
except Exception as e:
    print(f"   ❌ unlock_asset.py 测试失败: {e}")

print("\n===========================================")
print("   📋 测试完成")
print("===========================================")
