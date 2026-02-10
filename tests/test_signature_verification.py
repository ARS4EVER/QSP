#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试签名验证功能的脚本
"""

import os
import sys
import time

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 导入项目模块
from QSP.src.config import Config
from QSP.src.crypto_lattice.keygen import KeyGenerator
from QSP.src.crypto_lattice.signer import ThresholdSigner, SignatureAggregator

def test_signature_verification():
    """
    测试签名生成和验证功能
    """
    print("=" * 60)
    print("测试签名验证功能")
    print("=" * 60)
    
    # 1. 初始化密钥生成器和聚合器
    keygen = KeyGenerator()
    aggregator = SignatureAggregator()
    
    # 2. 生成密钥对
    print("1. 生成密钥对...")
    group_pk, party_keys = keygen.setup_system(5)  # 5个参与者
    print(f"   成功生成 {len(party_keys)} 个密钥对")
    print(f"   组公钥生成成功")
    
    # 3. 准备测试消息
    message = "Test message for signature verification"
    message_bytes = message.encode()
    timestamp = int(time.time())
    print(f"2. 测试消息: '{message}'")
    print(f"   时间戳: {timestamp}")
    
    # 4. 模拟多方协作签名
    print("3. 执行多方协作签名...")
    
    # 步骤1: 生成承诺
    commitments = []
    signers = []
    for i, key in enumerate(party_keys[:3]):  # 使用前3个密钥
        signer = ThresholdSigner(key['sk'], i)
        commitment = signer.phase1_commitment(timestamp)
        commitments.append(commitment)
        signers.append(signer)
        print(f"   参与者 {i+1} 生成承诺成功")
    
    # 步骤2: 聚合承诺
    W_sum = aggregator.aggregate_w_shares(commitments)
    print("   承诺聚合成功")
    
    # 步骤3: 生成响应（带重试机制）
    max_retries = 10
    for retry in range(max_retries):
        print(f"   尝试生成响应 (第 {retry+1}/{max_retries} 次)...")
        
        # 重新生成承诺
        commitments = []
        new_signers = []
        for i, key in enumerate(party_keys[:3]):
            signer = ThresholdSigner(key['sk'], i)
            commitment = signer.phase1_commitment(timestamp)
            commitments.append(commitment)
            new_signers.append(signer)
        
        # 聚合新的承诺
        W_sum = aggregator.aggregate_w_shares(commitments)
        
        # 尝试生成响应
        responses = []
        success = True
        for i, signer in enumerate(new_signers):
            response = signer.phase2_response(W_sum, message_bytes)
            if response:
                responses.append(response)
                print(f"   参与者 {i+1} 生成响应成功")
            else:
                print(f"   参与者 {i+1} 响应生成失败，需要重试")
                success = False
                break
        
        if success:
            signers = new_signers
            break
    
    if not responses:
        print("   多次尝试后响应生成仍失败")
        return False
    
    # 步骤4: 聚合响应
    Z_final = aggregator.aggregate_responses(responses)
    print("   响应聚合成功")
    
    # 步骤5: 生成挑战
    # 计算 W_true = HighBits(W_sum)
    alpha = 2 * Config.GAMMA2
    W_true = []
    for poly in W_sum:
        w_p = []
        for c in poly:
            from QSP.src.crypto_lattice.utils import LatticeUtils
            w_p.append(LatticeUtils.high_bits(c, alpha, Config.Q))
        W_true.append(w_p)
    
    # 打印 W_true 的前几个值，用于调试
    print(f"   W_true 前2个多项式的前5个系数: {W_true[0][:5]}, {W_true[1][:5]}")
    
    C_final = aggregator.derive_challenge(message_bytes, W_true, timestamp)
    print("   挑战生成成功")
    print(f"   挑战 C 的前5个系数: {C_final[:5]}")
    
    # 5. 验证签名
    print("4. 验证签名...")
    
    # 从组公钥中提取 T 和 rho
    T_group = group_pk['T']
    rho = group_pk['rho']
    
    # 重新扩展公共矩阵 A
    A = keygen.expand_a(rho)
    
    # 执行验证（传递 W_sum 使用距离检查）
    is_valid = aggregator.verify_final_signature(
        Z_final,
        C_final,
        T_group,
        A,
        message_bytes,
        timestamp,
        W_sum
    )
    
    if is_valid:
        print("✅ 签名验证成功！")
        print("   哈希检查通过")
        print("   范数检查通过")
        return True
    else:
        print("❌ 签名验证失败！")
        print("   可能的原因：")
        print("   - 哈希检查失败")
        print("   - 范数检查失败")
        return False

if __name__ == "__main__":
    success = test_signature_verification()
    print("=" * 60)
    if success:
        print("测试通过！签名验证功能正常")
    else:
        print("测试失败！签名验证功能存在问题")
    print("=" * 60)
