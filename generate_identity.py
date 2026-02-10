#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地身份铸造工具
基于格密码（LWE困难问题）生成高熵私钥向量和对应的公钥矩阵

运行方式:
    python generate_identity.py

产出:
    user.sk: 私钥文件（这是用户的最高机密，丢失即丧失资产所有权）
    user.pk: 公钥文件（类似于"钱包地址"，可公开发送给任何人）
"""

import os
import sys
import json
import time

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from QSP.src.config import Config
from QSP.src.crypto_lattice.keygen import KeyTool

# 确保输出目录存在
os.makedirs(Config.KEYS_DIR, exist_ok=True)

def generate_identity():
    """
    生成本地身份密钥对
    """
    print("=" * 70)
    print("🔐 本地身份铸造工具 (Identity Minting)")
    print("=" * 70)
    print("基于格密码（LWE困难问题）生成抗量子密钥对")
    print("此过程完全离线，不依赖任何服务器")
    print("=" * 70)
    
    # 生成密钥对
    pk, sk = KeyTool.generate_keypair()
    
    # 生成时间戳
    timestamp = int(time.time())
    
    # 保存私钥文件
    sk_filename = os.path.join(Config.KEYS_DIR, f'user_{timestamp}.sk')
    with open(sk_filename, 'w', encoding='utf-8') as f:
        json.dump(sk, f, indent=2, ensure_ascii=False)
    
    # 保存公钥文件
    pk_filename = os.path.join(Config.KEYS_DIR, f'user_{timestamp}.pk')
    with open(pk_filename, 'w', encoding='utf-8') as f:
        json.dump(pk, f, indent=2, ensure_ascii=False)
    
    print("=" * 70)
    print("✅ 身份铸造成功！")
    print(f"私钥文件: {sk_filename}")
    print(f"公钥文件: {pk_filename}")
    print("=" * 70)
    print("⚠️  重要提示:")
    print("1. 私钥文件是您的最高机密，务必妥善保管，丢失即丧失资产所有权")
    print("2. 公钥文件类似于'钱包地址'，可公开发送给任何人")
    print("3. 请备份私钥文件到安全的地方，例如加密的USB驱动器")
    print("=" * 70)

if __name__ == "__main__":
    generate_identity()
