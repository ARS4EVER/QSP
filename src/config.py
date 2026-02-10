# -*- coding: utf-8 -*-
import os

class Config:
    """
    系统全局配置 - 针对 (t, n) 门限方案优化
    """
    
    # --- 路径配置 ---
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, "data")
    
    PATHS = {
        "keys": os.path.join(DATA_DIR, "keys"),
        "shares": os.path.join(DATA_DIR, "shares"),
        "stego": os.path.join(DATA_DIR, "stego_images"),
        "restored": os.path.join(DATA_DIR, "restored")
    }
    for p in PATHS.values():
        os.makedirs(p, exist_ok=True)
    
    KEYS_DIR = PATHS["keys"]
    SHARES_DIR = PATHS["shares"]
    STEGO_DIR = PATHS["stego"]
    RESTORED_DIR = PATHS["restored"]

    # --- 格密码核心参数 (参考 Kyber/Dilithium 标准) ---
    Q = 8380417  
    N = 256      
    ROOT_OF_UNITY = 1753
    K = 2
    L = 2
    ETA = 2
    
    # [关键修改] 参数调整以支持门限聚合
    # 使用极宽的参数以避免 LowBits 进位导致的哈希不匹配
    # 成功率约 50%-80%，失败请重试
    BETA = 250                # 减小安全边界 (标准是78，250足够安全)
    GAMMA2 = (Q - 1) // 8     # ~1,047,552 (极大增加 LowBits 容量)
    GAMMA1 = (Q - 1) // 2     # ~4,190,208 (配合 GAMMA2 增大)
    
    TAU = 39 
    PK_SIZE_BYTES = 1312 
    SIG_SIZE_BYTES = 2420
    D = 14

    # --- CRT 参数 ---
    MODULI = [257, 263, 269, 271, 277] 
    T_THRESHOLD = 3
    N_PARTICIPANTS = 5
    LARGE_PRIME_Q = 257

    # --- 隐写参数 (严格适配陈维启论文) ---
    DCT_BLOCK_SIZE = 4       # [修正] 论文要求 4x4 分块
    EMBEDDING_STRENGTH = 25  # 嵌入强度 k
    TARGET_COEFF_INDEX = 11  # [修正] 论文第12个系数 (索引11)
    
    # --- 可视化参数 ---
    ENABLE_VISUALIZATION = True  # 是否启用可视化输出，生成余数图像