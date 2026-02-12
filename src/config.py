# -*- coding: utf-8 -*-
import os

class Config:
    """
    系统全局配置 - 纯净版 (移除隐写相关配置)
    """
    
    # --- 路径配置 ---
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, "data")
    
    PATHS = {
        "keys": os.path.join(DATA_DIR, "keys"),
        "shares": os.path.join(DATA_DIR, "shares"), # 存放加密分片文件
        "restored": os.path.join(DATA_DIR, "restored")
    }
    for p in PATHS.values():
        os.makedirs(p, exist_ok=True)
    
    KEYS_DIR = PATHS["keys"]
    SHARES_DIR = PATHS["shares"]
    RESTORED_DIR = PATHS["restored"]

    # --- 格密码核心参数 (保持不变) ---
    Q = 8380417  
    N = 256      
    ROOT_OF_UNITY = 1753
    K = 2
    L = 2
    ETA = 2
    
    BETA = 250
    GAMMA2 = (Q - 1) // 8
    GAMMA1 = (Q - 1) // 2
    
    TAU = 39 
    PK_SIZE_BYTES = 1312 
    SIG_SIZE_BYTES = 2420
    D = 14

    # --- CRT 参数 ---
    MODULI = [257, 263, 269, 271, 277] 
    T_THRESHOLD = 3
    N_PARTICIPANTS = 5
    LARGE_PRIME_Q = 257

    # --- 文件后缀配置 ---
    SHARE_EXT = ".dat" # 加密分片文件的后缀