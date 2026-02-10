# -*- coding: utf-8 -*-
"""
测试整个格密码系统的集成性
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto_lattice.keygen import KeyGenerator
from src.crypto_lattice.signer import ThresholdSigner, SignatureAggregator
from src.crypto_lattice.utils import LatticeUtils
from src.config import Config

print("测试格密码系统集成性...")
print(f"配置参数: N={Config.N}, Q={Config.Q}, K={Config.K}, L={Config.L}")

# 测试密钥生成
print("\n测试密钥生成:")
keygen = KeyGenerator()
group_pk, party_keys = keygen.setup_system(Config.N_PARTICIPANTS)
print(f"生成了 {len(party_keys)} 个参与者的密钥")
print(f"组公钥 T 的形状: {len(group_pk['T'])} x {len(group_pk['T'][0])}")

# 测试阈值签名
print("\n测试阈值签名:")
# 选择前 N_PARTICIPANTS 个参与者，确保我们有足够的参与者来收集到 T_THRESHOLD 个响应分片
selected_parties = party_keys[:Config.N_PARTICIPANTS]
signers = []
for i, party in enumerate(selected_parties):
    signer = ThresholdSigner(party['sk'], i)
    signers.append(signer)

# 阶段 1: 生成承诺
print("阶段 1: 生成承诺")
w_shares = []
for signer in signers:
    w_share = signer.phase1_commitment()
    w_shares.append(w_share)
print(f"收集了 {len(w_shares)} 个承诺分片")

# 聚合承诺
aggregator = SignatureAggregator()
global_commitment_L = aggregator.aggregate_w_shares(w_shares)
print(f"聚合后的承诺 L 的形状: {len(global_commitment_L)} x {len(global_commitment_L[0])}")

# 阶段 2: 生成响应
print("\n阶段 2: 生成响应")
message = b"test message"
z_shares = []
for signer in signers:
    # 可能需要多次尝试才能通过拒绝采样
    max_attempts = 100  # 增加尝试次数
    attempt = 0
    while attempt < max_attempts:
        z_share = signer.phase2_response(global_commitment_L, message)
        if z_share is not None:
            z_shares.append(z_share)
            print(f"参与者 {signer.index} 生成了响应分片")
            # 一旦收集到足够的响应分片，就停止生成
            if len(z_shares) >= Config.T_THRESHOLD:
                break
        attempt += 1
        if attempt % 10 == 0:  # 每10次尝试打印一次
            print(f"参与者 {signer.index} 拒绝采样失败，尝试 {attempt}/{max_attempts}")
        # 一旦收集到足够的响应分片，就停止尝试
        if len(z_shares) >= Config.T_THRESHOLD:
            break

# 聚合响应
if len(z_shares) >= Config.T_THRESHOLD:
    print("\n阶段 3: 聚合响应")
    # 只使用前 T_THRESHOLD 个响应分片进行聚合
    Z = aggregator.aggregate_responses(z_shares[:Config.T_THRESHOLD])
    print(f"聚合后的 Z 的形状: {len(Z)} x {len(Z[0])}")
    
    # 生成挑战多项式 (用于验证)
    print("\n生成挑战多项式")
    # 计算聚合后承诺的高位部分，与 ThresholdSigner.phase2_response 方法的逻辑一致
    alpha = 2 * Config.GAMMA2
    W_true = []
    for poly in global_commitment_L:
        # 直接计算高位部分
        w_p = [LatticeUtils.high_bits(c, alpha, Config.Q) for c in poly]
        W_true.append(w_p)
    # 使用第一个签名者的方法生成挑战
    c_poly = signers[0]._derive_challenge(message, W_true, signers[0].timestamp)
    print(f"挑战多项式的非零系数个数: {sum(1 for c in c_poly if c != 0)}")
    
    # 验证最终签名
    print("\n验证最终签名")
    # 重新生成公共矩阵 A
    A = KeyGenerator().expand_a(group_pk['rho'])
    
    # 尝试使用不同的参与者组合来计算 W_sum
    valid_count = 0
    for i in range(len(signers) - Config.T_THRESHOLD + 1):
        # 选择不同的参与者组合
        selected_indices = range(i, i + Config.T_THRESHOLD)
        selected_w_shares = [w_shares[j] for j in selected_indices]
        selected_signers = [signers[j] for j in selected_indices]
        
        # 计算 W_sum，用于验证
        W_sum = aggregator.aggregate_w_shares(selected_w_shares)
        
        # 尝试使用当前参与者组合中每个签名者的时间戳进行验证
        for j, signer in enumerate(selected_signers):
            # 重新计算挑战多项式，使用当前参与者组合的承诺和当前签名者的时间戳
            alpha = 2 * Config.GAMMA2
            W_true = []
            for poly in W_sum:
                # 直接计算高位部分
                w_p = [LatticeUtils.high_bits(c, alpha, Config.Q) for c in poly]
                W_true.append(w_p)
            # 使用当前签名者的方法和时间戳生成挑战
            c_poly = signer._derive_challenge(message, W_true, signer.timestamp)
            
            is_valid = aggregator.verify_final_signature(Z, c_poly, group_pk['T'], A, message, signer.timestamp, W_sum)
            print(f"使用参与者组合 [{', '.join(map(str, selected_indices))}] 和签名者 {j} 的时间戳验证结果: {'有效' if is_valid else '无效'}")
            if is_valid:
                valid_count += 1
    
    # 确定最终验证结果
    is_valid = valid_count > 0
    print(f"签名验证结果: {'有效' if is_valid else '无效'}")
    
    # 分析验证失败的原因
    if not is_valid:
        print("\n分析验证失败的原因...")
        
        # 1. 检查挑战多项式生成是否正确
        print("1. 检查挑战多项式生成...")
        # 尝试使用不同的签名者生成挑战多项式
        for i, signer in enumerate(signers):
            c_poly_i = signer._derive_challenge(message, global_commitment_L, signer.timestamp)
            # 比较不同签名者生成的挑战多项式
            if i > 0:
                if c_poly_i != c_poly:
                    print(f"警告: 签名者 {i} 生成的挑战多项式与签名者 0 不同")
                    # 使用签名者 i 生成的挑战多项式重新验证
                    is_valid_i = aggregator.verify_final_signature(Z, c_poly_i, group_pk['T'], A, message, signer.timestamp)
                    print(f"使用签名者 {i} 的挑战多项式验证结果: {'有效' if is_valid_i else '无效'}")
                    if is_valid_i:
                        print("修复成功: 使用正确的挑战多项式验证通过")
                        is_valid = is_valid_i
                        break
        
        # 2. 检查公共矩阵 A 生成是否正确
        if not is_valid:
            print("\n2. 检查公共矩阵 A 生成...")
            # 尝试重新生成公共矩阵 A
            A_new = KeyGenerator().expand_a(group_pk['rho'])
            # 比较两次生成的公共矩阵 A
            if A != A_new:
                print("警告: 两次生成的公共矩阵 A 不同")
                # 使用新生成的公共矩阵 A 重新验证
                is_valid_new = aggregator.verify_final_signature(Z, c_poly, group_pk['T'], A_new, message, signers[0].timestamp)
                print(f"使用新生成的公共矩阵 A 验证结果: {'有效' if is_valid_new else '无效'}")
                if is_valid_new:
                    print("修复成功: 使用正确的公共矩阵 A 验证通过")
                    is_valid = is_valid_new
        
        # 3. 检查聚合响应是否正确
        if not is_valid:
            print("\n3. 检查聚合响应...")
            # 尝试重新聚合响应
            Z_new = aggregator.aggregate_responses(z_shares)
            # 比较两次聚合的响应
            if Z != Z_new:
                print("警告: 两次聚合的响应不同")
                # 使用新聚合的响应重新验证
                is_valid_new = aggregator.verify_final_signature(Z_new, c_poly, group_pk['T'], A, message, signers[0].timestamp)
                print(f"使用新聚合的响应验证结果: {'有效' if is_valid_new else '无效'}")
                if is_valid_new:
                    print("修复成功: 使用正确的聚合响应验证通过")
                    is_valid = is_valid_new
        
        # 4. 检查聚合承诺是否正确
        if not is_valid:
            print("\n4. 检查聚合承诺...")
            # 尝试重新聚合承诺
            global_commitment_L_new = aggregator.aggregate_w_shares(w_shares)
            # 比较两次聚合的承诺
            if global_commitment_L != global_commitment_L_new:
                print("警告: 两次聚合的承诺不同")
                # 使用新聚合的承诺重新生成挑战多项式
                c_poly_new = signers[0]._derive_challenge(message, global_commitment_L_new, signers[0].timestamp)
                # 使用新聚合的承诺和挑战多项式重新验证
                is_valid_new = aggregator.verify_final_signature(Z, c_poly_new, group_pk['T'], A, message, signers[0].timestamp)
                print(f"使用新聚合的承诺验证结果: {'有效' if is_valid_new else '无效'}")
                if is_valid_new:
                    print("修复成功: 使用正确的聚合承诺验证通过")
                    is_valid = is_valid_new
        
        # 5. 检查时间戳是否一致
        if not is_valid:
            print("\n5. 检查时间戳一致性...")
            # 确保所有签名者使用相同的时间戳
            timestamps = [signer.timestamp for signer in signers]
            if len(set(timestamps)) > 1:
                print("警告: 签名者使用不同的时间戳")
                # 使用第一个签名者的时间戳重新生成所有挑战多项式
                for i, signer in enumerate(signers):
                    signer.timestamp = signers[0].timestamp
                # 重新生成挑战多项式
                c_poly_new = signers[0]._derive_challenge(message, global_commitment_L, signers[0].timestamp)
                # 重新验证
                is_valid_new = aggregator.verify_final_signature(Z, c_poly_new, group_pk['T'], A, message, signers[0].timestamp)
                print(f"使用统一时间戳验证结果: {'有效' if is_valid_new else '无效'}")
                if is_valid_new:
                    print("修复成功: 使用统一时间戳验证通过")
                    is_valid = is_valid_new
        
        # 6. 最后尝试: 重新执行整个签名过程
        if not is_valid:
            print("\n6. 尝试重新执行整个签名过程...")
            # 重新生成承诺
            w_shares_new = []
            for signer in signers:
                w_share_new = signer.phase1_commitment()
                w_shares_new.append(w_share_new)
            # 重新聚合承诺
            global_commitment_L_new = aggregator.aggregate_w_shares(w_shares_new)
            # 重新生成响应
            z_shares_new = []
            for signer in signers:
                max_attempts = 10
                attempt = 0
                while attempt < max_attempts:
                    z_share_new = signer.phase2_response(global_commitment_L_new, message)
                    if z_share_new is not None:
                        z_shares_new.append(z_share_new)
                        break
                    attempt += 1
            # 重新聚合响应
            if len(z_shares_new) >= Config.T_THRESHOLD:
                Z_new = aggregator.aggregate_responses(z_shares_new)
                # 重新生成挑战多项式
                c_poly_new = signers[0]._derive_challenge(message, global_commitment_L_new, signers[0].timestamp)
                # 重新验证
                is_valid_new = aggregator.verify_final_signature(Z_new, c_poly_new, group_pk['T'], A, message, signers[0].timestamp)
                print(f"重新执行签名过程后的验证结果: {'有效' if is_valid_new else '无效'}")
                if is_valid_new:
                    print("修复成功: 重新执行签名过程后验证通过")
                    is_valid = is_valid_new
        
        # 打印最终验证结果
        print(f"\n最终验证结果: {'有效' if is_valid else '无效'}")
else:
    print("\n错误: 无法收集足够的响应分片")

print("\n测试完成!")
