"""
src/config.py
[系统全局配置 - Single Source of Truth]

重构版: 彻底剥离了底层格密码学数学常量。
专为"标准抗量子身份认证 + ML-KEM 通道 + Shamir 门限容灾"架构设计。
"""

class SigParams:
    """
    [身份认证参数配置]
    对应算法: ML-DSA-44 (即 NIST Dilithium2)
    用于: 节点身份鉴权、防止中间人攻击 (单节点标准签名)
    """
    NAME = "ML-DSA-44"
    
    # --- 网络传输参数 (字节) ---
    # Public Key = 1312 bytes
    PK_SIZE = 1312  
    # Signature ≈ 2420 bytes
    # 注: 标准 Dilithium2 签名尺寸为 2420 字节。
    # 由于 2420 > 网络 MTU(1400)，这要求底层 RUDP 必须具备可靠的大包分片能力。
    SIG_SIZE = 2420 

class KEMParams:
    """
    [抗量子握手参数配置]
    对应算法: ML-KEM-512 (即 NIST Kyber512)
    用于: 建立端到端加密通道 (Secure Channel)
    """
    NAME = "ML-KEM-512"
    
    # --- 网络传输参数 (字节) ---
    # Public Key Size: 800 bytes
    PK_SIZE = 800   
    # Ciphertext Size: 768 bytes
    CT_SIZE = 768   
    # Shared Secret (AES Session Key) Size: 32 bytes (256 bits)
    SS_SIZE = 32    

class ThresholdParams:
    """
    [数据容灾门限参数]
    对应算法: Shamir's Secret Sharing (SSS)
    用于: 决定多少个节点可以恢复出原始的机密数据 (如文件或主密钥)
    """
    # 参与者总数 n (例如: 5个节点组成一个组分布存储数据切片)
    n_participants = 5
    
    # 门限值 t (必须满足 1 < t <= n)
    # 只有通过安全通道收集到 >= t 个有效切片，Host 才能还原原始机密
    t = 3 

class NetworkParams:
    """
    [RUDP 可靠传输参数]
    用于: 解决 UDP 丢包、乱序和抗量子大包分片重组问题
    """

    MTU = 1400
    
    # 拥塞控制初始窗口大小 (单位: 包)
    INITIAL_CWND = 1.0
    
    # 握手超时时间 (秒)
    HANDSHAKE_TIMEOUT = 5.0
    
    # 丢包重传超时 (秒)
    RTO_INITIAL = 0.2  # 200ms
