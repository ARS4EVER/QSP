import hashlib
import secrets
import pickle
import numpy as np
from src.config import Config
from src.crypto_lattice.utils import LatticeUtils
from src.crypto_lattice.ntt import polymul_rq

class LatticeEncryptor:
    """
    抗量子混合加密器 (Hybrid Encryption)
    机制:
    1. KEM (Key Encapsulation): 使用 LWE 公钥加密 32字节的随机 SessionKey。
    2. DEM (Data Encapsulation): 使用 SessionKey (SHAKE256) 对任意长度数据进行流加密。
    """

    @staticmethod
    def encrypt_data(target_pk, raw_data_bytes):
        """
        [Dealer端调用]
        输入: 接收者公钥, 原始数据
        输出: 序列化的密文包 (bytes)
        """
        # 1. 生成一次性会话密钥 K (32 bytes)
        session_key = secrets.token_bytes(32)
        
        # 2. 使用 Lattice 公钥加密 session_key -> cipher_key
        # (模拟 Kyber 的封装过程)
        cipher_key = LatticeEncryptor._lwe_encrypt_key(target_pk, session_key)
        
        # 3. 使用 session_key 对数据进行流加密 -> cipher_data
        # 生成与数据等长的密钥流 (One-Time Pad 变体)
        keystream = hashlib.shake_256(session_key).digest(len(raw_data_bytes))
        cipher_data = bytes(a ^ b for a, b in zip(raw_data_bytes, keystream))
        
        # 4. 打包所有数据
        encrypted_package = {
            "cipher_key": cipher_key,
            "cipher_data": cipher_data
        }
        return pickle.dumps(encrypted_package)

    @staticmethod
    def decrypt_data(sk, encrypted_package_bytes):
        """
        [User端调用] 完全离线解密
        输入: 本地私钥, 提取出的密文包
        输出: 原始数据 (如果私钥匹配) 或 None
        """
        try:
            # 1. 反序列化
            package = pickle.loads(encrypted_package_bytes)
            cipher_key = package['cipher_key']
            cipher_data = package['cipher_data']
            
            # 2. 使用私钥解密出 session_key
            session_key = LatticeEncryptor._lwe_decrypt_key(sk, cipher_key)
            
            if not session_key:
                return None
                
            # 3. 使用 session_key 解密数据
            keystream = hashlib.shake_256(session_key).digest(len(cipher_data))
            raw_data = bytes(a ^ b for a, b in zip(cipher_data, keystream))
            
            return raw_data
            
        except Exception as e:
            print(f"[Decrypt] Error: {e}")
            return None

    # --- LWE 底层数学逻辑 (简化版) ---
    
    @staticmethod
    def _lwe_encrypt_key(pk, key_bytes):
        """用 LWE 公钥加密 32字节 key"""
        N, Q = Config.N, Config.Q
        
        # 编码: 将 bytes 转为多项式消息 m (Bit 1 -> Q/2, Bit 0 -> 0)
        m_poly = [0] * N
        bits = ''.join(f'{b:08b}' for b in key_bytes)
        for i, bit in enumerate(bits):
            if bit == '1': 
                m_poly[i] = Q // 2
            
        # 准备 LWE 矩阵 A
        A = LatticeUtils.gen_matrix(pk['public_seed'], Config.K, Config.L, N, Q)
        t = pk['t']
        
        # 采样随机数 r, e1, e2
        r = [LatticeUtils.sample_poly_centered(N, Config.ETA) for _ in range(Config.K)]
        e1 = [LatticeUtils.sample_poly_centered(N, Config.ETA) for _ in range(Config.L)]
        e2 = LatticeUtils.sample_poly_centered(N, Config.ETA)
        
        # 计算 u = A^T * r + e1
        u = []
        for j in range(Config.L):
            acc = [0] * N
            for i in range(Config.K):
                prod = polymul_rq(A[i][j], r[i])
                acc = LatticeUtils.poly_add(acc, prod, Q)
            u.append(LatticeUtils.poly_add(acc, e1[j], Q))
            
        # 计算 v = t^T * r + e2 + m
        v = [0] * N
        for i in range(Config.K):
            prod = polymul_rq(t[i], r[i])
            v = LatticeUtils.poly_add(v, prod, Q)
        v = LatticeUtils.poly_add(v, e2, Q)
        v = LatticeUtils.poly_add(v, m_poly, Q)
        
        return {"u": u, "v": v}

    @staticmethod
    def _lwe_decrypt_key(sk, cipher_struct):
        """用 LWE 私钥解密得到 32字节 key"""
        N, Q = Config.N, Config.Q
        u = cipher_struct['u']
        v = cipher_struct['v']
        s = sk['s']
        
        # 解密公式: m' = v - s^T * u
        su = [0] * N
        for i in range(Config.L):
            prod = polymul_rq(s[i], u[i])
            su = LatticeUtils.poly_add(su, prod, Q)
            
        m_noisy = LatticeUtils.poly_sub(v, su, Q)
        
        # 解码: 阈值判决 (是否接近 Q/2)
        bits = []
        lower, upper = Q // 4, 3 * Q // 4
        for coeff in m_noisy:
            if lower < coeff < upper:
                bits.append('1')
            else:
                bits.append('0')
        
        # 转回 bytes
        try:
            bit_str = "".join(bits[:256]) # 只取前256位(32字节)
            return int(bit_str, 2).to_bytes(32, 'big')
        except:
            return None