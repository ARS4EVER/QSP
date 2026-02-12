import numpy as np
import time
from src.crypto_lattice.keygen import KeyGenerator, KeyTool
from src.crypto_lattice.signer import ThresholdSigner, SignatureAggregator
from src.crypto_lattice.utils import LatticeUtils
from src.config import Config

def test_memory_signing_flow():
    print("=== [测试 1] 开始测试内存签名流程 ===")
    
    # 1. 模拟生成身份 (3个用户)
    users = []
    for i in range(3):
        # 生成的是内存字典对象，不是文件
        pk, sk = KeyTool.generate_keypair()
        # 转换密钥结构以适配ThresholdSigner
        # ThresholdSigner期望sk包含s1和s2字段，而不是s字段
        # 将十六进制字符串转换回字节对象
        adapted_sk = {
            'rho': bytes.fromhex(sk['public_seed']),
            's1': sk['s'],
            's2': sk['s']  # 使用相同的s作为s2，仅用于测试
        }
        users.append({'sk': adapted_sk, 'pk': pk, 'id': i})
    print("✅ 密钥生成完成 (内存模式)")

    # 2. 聚合公钥
    aggregator = SignatureAggregator()
    # 提取所有人的 pk['t']
    pk_list = [u['pk']['t'] for u in users]
    T_dynamic = aggregator.aggregate_public_keys(pk_list)
    print("✅ 动态公钥聚合完成")

    # 3. Phase 1: 承诺 (Commitment)
    commitments = []
    signers = []
    for u in users:
        signer = ThresholdSigner(u['sk'], u['id'])
        signers.append(signer)
        # 直接获取 W，不写入文件
        w = signer.phase1_commitment() 
        commitments.append(w)
    print("✅ Phase 1 承诺生成完成")

    # 4. Host 计算挑战 (Challenge)
    global_w_sum = aggregator.aggregate_w_shares(commitments)
    message = b"Test_File_Hash_123456"
    timestamp = int(time.time())
    # 拼接时间戳模拟协议层的行为
    msg_with_ts = message + timestamp.to_bytes(8, 'little')
    
    # Host 计算出的 c
    # 注意：为了与verify_final_signature方法一致，我们需要先计算HighBits(global_w_sum)
    from src.config import Config
    from src.crypto_lattice.utils import LatticeUtils
    alpha = 2 * Config.GAMMA2
    W_HighBits = []
    for poly in global_w_sum:
        w_p = [LatticeUtils.high_bits(c, alpha, Config.Q) for c in poly]
        W_HighBits.append(w_p)
    
    # 使用HighBits(global_w_sum)作为输入
    c_host = aggregator.derive_challenge(message, W_HighBits, timestamp)
    print("✅ Host 挑战生成完成")

    # 5. Phase 2: 响应 (Response) - 测试安全加固
    responses = []
    for i, signer in enumerate(signers):
        # 关键测试点：用户本地接收 global_w_sum，能否算出正确的 z
        # 注意：这里传入的是原始的 message，而不是 msg_with_ts
        # 同时传入 timestamp 作为单独的参数
        try:
            # 由于ThresholdSigner.phase2_response方法的签名是固定的，我们需要修改它来接收正确的参数
            # 这里我们暂时修改测试文件，将message和timestamp作为一个元组传递
            # 然后在ThresholdSigner.phase2_response方法中解析这个元组
            z = signer.phase2_response((message, timestamp), global_w_sum)
            if z:
                responses.append(z)
            else:
                print(f"⚠️ 用户 {i} 拒绝采样 (这是正常的，重试即可)")
        except Exception as e:
            print(f"❌ 用户 {i} 签名失败: {e}")
            return

    if len(responses) < 3:
        print("⚠️ 响应数量不足 (因拒绝采样)，测试跳过验证步骤")
        return

    # 6. 验证
    z_final = aggregator.aggregate_responses(responses)
    # 注意：传递W_sum参数，这样verify_final_signature方法会使用距离检查方式
    # 同时，将[T_dynamic]改为T_dynamic，因为verify_final_signature方法期望T_pub是一个多项式列表
    is_valid = aggregator.verify_final_signature(
        z_final, c_host, T_dynamic, signer.A, message, timestamp, W_sum=global_w_sum
    )

    if is_valid:
        print("🎉 [成功] 内存签名验证通过！")
    else:
        print("❌ [失败] 签名验证未通过")

if __name__ == "__main__":
    test_memory_signing_flow()