"""
系统全局配置 - Single Source of Truth
"""

import os
import sys

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "data")
KEYS_DIR = os.path.join(DATA_DIR, "keys")
SHARES_DIR = os.path.join(DATA_DIR, "shares")
MANIFESTS_DIR = SHARES_DIR


class SigParams:
    """ML-DSA-44 签名参数"""
    NAME = "ML-DSA-44"
    PK_SIZE = 1312  # 公钥字节数
    SIG_SIZE = 2420  # 签名字节数


class KEMParams:
    """ML-KEM-512 密钥封装参数"""
    NAME = "ML-KEM-512"
    PK_SIZE = 800   # 公钥字节数
    CT_SIZE = 768   # 密文字节数
    SS_SIZE = 32    # 共享秘密字节数


class ThresholdParams:
    """Shamir 秘密共享阈值参数"""
    n_participants = 5  # 总参与者数量
    t = 3  # 阈值（需要的最少份额数）


class NetworkParams:
    """网络传输参数"""
    MTU = 1400  # 最大传输单元
    INITIAL_CWND = 1.0  # 初始拥塞窗口
    HANDSHAKE_TIMEOUT = 5.0  # 握手超时时间
    RTO_INITIAL = 0.2  # 初始重传超时
