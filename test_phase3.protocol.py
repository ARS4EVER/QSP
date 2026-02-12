# test_phase3.protocol.py

import threading
import time
import json
import pickle
import base64
import numpy as np
import secrets
from unittest.mock import MagicMock, patch

# === 导入核心模块 ===
from src.core.recovery_session import RecoveryHostSession, RecoveryParticipantSession
from src.crypto_lattice.keygen import KeyGenerator

# 仅 Mock 解密函数（因为它涉及大文件读取和解密，与网络协议逻辑无关）
# 这样测试可以无需准备真实的 Carrier 图片
def mock_decrypt_data(sk, cipher_struct):
    # print("    [Mock] 正在解密数据...")
    dummy_share = {
        'index': 1, 
        'data': np.array([101, 102, 103], dtype=np.int64) 
    }
    return pickle.dumps(dummy_share)

def run_integration_test():
    print("="*60)
    print("🚀 Phase 3 真实网络集成测试 (LAN Mode)")
    print("="*60)

    # 1. 准备密钥环境
    print("[Setup] 生成测试密钥对...")
    keygen = KeyGenerator()
    
    # 必须生成公共种子 rho，保证双方数学参数一致
    rho = secrets.token_bytes(32)
    
    alice_pk, alice_sk = keygen.generate_party_key(rho) # Host
    bob_pk, bob_sk = keygen.generate_party_key(rho)     # Participant
    
    # 2. 构造清单 (Manifest)
    manifest = [
        {
            "owner_alias": "Bob (The Assistant)",
            "public_key_t": bob_pk['t'], 
            "threshold": 2
        }
    ]
    target_hash = b"mock_file_hash_123456"

    # 3. 初始化 Host Session (Alice)
    print("[Host] 初始化 Alice 的会话 (LAN Mode)...")
    
    # [关键] 传入 lan_mode=True，使其内部使用 LanP2PManager
    host = RecoveryHostSession(alice_sk, alice_pk, lan_mode=True)
    
    # Mock 重构器 (防止因数据不足报错)
    host.reconstructor = MagicMock()
    host.reconstructor.reconstruct_from_memory.return_value = "🎉 RECOVERED_SECRET_IMAGE_DATA 🎉"
    
    invitation_code = host.create_invitation()
    print(f"[Host] 邀请码: {invitation_code[:20]}...")

    # 4. 初始化 Participant Session (Bob)
    print("[Part] 初始化 Bob 的会话 (LAN Mode)...")
    
    # [关键] 传入 lan_mode=True
    part = RecoveryParticipantSession(bob_sk, bob_pk, lan_mode=True)
    
    # Mock 隐写提取器
    part.orchestrator = MagicMock()
    part.orchestrator.extract_share_bytes.return_value = b"MOCK_ENCRYPTED_BYTES"
    
    # 自动同意授权
    part.on_approval_request = lambda h: True

    # === 开始并发运行 ===
    
    # 线程 A: Host 启动恢复流程
    def run_host_logic():
        time.sleep(2) # 等待 Bob 连接并发送 HELLO
        print("\n[Host] >>> 启动恢复流程 (Start Recovery)...")
        host.start_recovery(manifest, target_hash)

    # 线程 B: Participant 连接
    def run_part_logic():
        time.sleep(1) # 稍等 Host 就绪
        print(f"[Part] >>> 连接 Host...")
        # 仅 Patch 解密函数
        with patch('src.crypto_lattice.encryptor.LatticeEncryptor.decrypt_data', side_effect=mock_decrypt_data):
            part.join_session(invitation_code, "dummy_carrier.png", alice_pk)

    t_host = threading.Thread(target=run_host_logic, daemon=True)
    t_part = threading.Thread(target=run_part_logic, daemon=True)

    t_host.start()
    t_part.start()

    # 5. 监控状态
    # 最多等待 15 秒
    for i in range(15):
        time.sleep(1)
        # 检查是否完成
        if host.state.name == "FINISHED" or host.state.name == "RECONSTRUCTING":
            print(f"\n✅ 测试通过! Host 状态: {host.state.name}")
            return
        
        # 打印进度
        verified_count = sum(1 for p in host.peers_data.values() if p.get('verified'))
        if i % 3 == 0:
            print(f"   [Time {i}s] HostState={host.state.name} | VerifiedPeers={verified_count}")

    print("\n❌ 测试超时! 流程未在规定时间内完成。")
    print(f"Final Host State: {host.state}")
    print(f"Host Peers Data: {host.peers_data}")

if __name__ == "__main__":
    run_integration_test()