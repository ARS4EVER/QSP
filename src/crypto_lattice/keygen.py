"""
Module 1: Key Generation
文件路径: src/crypto_lattice/keygen.py

负责生成 LTSS 系统的公私钥对。
实现了矩阵 A 的扩展生成、短向量 s 的采样以及公钥 t 的计算与压缩。
"""

import numpy as np
import secrets
import os
import json
import time
from ..config import Config
from .ntt import polymul_rq
from .utils import LatticeUtils

class KeyGenerator:
    """
    密钥生成器
    注意: 这是一个 'Trusted Dealer' (可信中心) 的简化实现。
    在真实的门限环境中，应该使用分布式密钥生成 (DKG) 协议，
    但这超出了当前代码框架的范围。本实现模拟生成各方私钥。
    """
    def __init__(self):
        self.k = Config.K
        self.l = Config.L
        self.q = Config.Q
        self.eta = Config.ETA
        self.n = Config.N

    def expand_a(self, seed):
        """
        从种子扩展生成公共矩阵 A (K x L)
        """
        # 简单使用 numpy 模拟 SHAKE-128 扩展
        # 实际应用中应使用 hashlib.shake_128
        seed_int = int.from_bytes(seed[:4], 'little')
        np.random.seed(seed_int)
        
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.l):
                poly = np.random.randint(0, self.q, self.n).tolist()
                row.append(poly)
            A.append(row)
        return A

    def generate_party_key(self, rho):
        """
        为单个参与者生成密钥对 (s_i, t_i)
        公钥 t_i = A * s1_i + s2_i
        """
        A = self.expand_a(rho)
        
        # 采样私钥向量 s1 (L维) 和 误差向量 s2 (K维)
        # 范围 [-eta, eta]
        s1 = [np.random.randint(-self.eta, self.eta + 1, self.n).tolist() for _ in range(self.l)]
        s2 = [np.random.randint(-self.eta, self.eta + 1, self.n).tolist() for _ in range(self.k)]
        
        # 计算部分公钥 t_i
        # 根据CRYSTALS-Dilithium标准，公钥 t_i = A @ s1
        # s2 是私钥的一部分，不应该包含在公钥中
        # 使用直接加法，确保与签名生成和验证过程的处理方式一致
        t = []
        for i in range(self.k):
            row_res = [0] * self.n
            for j in range(self.l):
                prod = polymul_rq(A[i][j], s1[j])
                # 对 prod 进行中心化处理
                centered_prod = [LatticeUtils.center_mod(c, self.q) for c in prod]
                # 直接相加
                for m in range(self.n):
                    row_res[m] += centered_prod[m]
            t.append(row_res)
            
        # sk_i 包含 s1 (用于签名) 和 s2 (用于 LowBits 检查中的 Ce 计算)
        sk = {
            'rho': rho,
            's1': s1,
            's2': s2 
        }
        
        pk = {
            'rho': rho,
            't': t
        }
        
        return pk, sk

    def setup_system(self, n_parties):
        """
        系统初始化 (模拟 Trusted Setup)
        """
        rho = secrets.token_bytes(32)
        party_keys = []
        
        for i in range(n_parties):
            pk, sk = self.generate_party_key(rho)
            party_keys.append({'pk': pk, 'sk': sk, 'id': i})
            
        # 计算组公钥 T = sum(t_i)
        # 初始化 T 为 0
        T = [[0]*self.n for _ in range(self.k)]
        for p in party_keys:
            t_i = p['pk']['t']
            for k in range(self.k):
                # 直接相加，不使用 poly_add（避免标准取模）
                for i in range(self.n):
                    T[k][i] += t_i[k][i]
                
        # 构造组公钥（rho 为字节类型）
        group_pk = {'rho': rho, 'T': T}
        
        # 准备保存到文件的组公钥结构（将 rho 转换为十六进制字符串）
        group_pk_to_save = {'rho': rho.hex(), 'T': T}
        
        # 保存组公钥和各方密钥
        timestamp = int(time.time())
        group_pk_filename = os.path.join(Config.KEYS_DIR, f'group_public_key_{timestamp}.json')
        
        # 保存组公钥
        with open(group_pk_filename, 'w') as f:
            json.dump(group_pk_to_save, f, indent=2)
        
        # 保存各方密钥
        for i, p in enumerate(party_keys):
            pk = p['pk']
            sk = p['sk']
            
            # 准备保存到文件的密钥结构（将 rho 转换为十六进制字符串）
            pk_to_save = {
                'rho': pk['rho'].hex(),
                't': pk['t']
            }
            
            sk_to_save = {
                'rho': sk['rho'].hex(),
                's1': sk['s1'],
                's2': sk['s2']
            }
            
            pk_filename = os.path.join(Config.KEYS_DIR, f'party_{i}_public_key_{timestamp}.json')
            sk_filename = os.path.join(Config.KEYS_DIR, f'party_{i}_secret_key_{timestamp}.json')
            
            with open(pk_filename, 'w') as f:
                json.dump(pk_to_save, f, indent=2)
            
            with open(sk_filename, 'w') as f:
                json.dump(sk_to_save, f, indent=2)
        
        print(f"[KeyGen] System setup for {n_parties} parties complete.")
        print(f"[KeyGen] 组公钥已保存到: {group_pk_filename}")
        print(f"[KeyGen] 各方密钥已保存到: {Config.KEYS_DIR} 目录")
        
        return group_pk, party_keys
        
    def sample_secret_poly(self):
        """
        采样私钥多项式。
        系数服从 [-eta, eta] 的均匀分布。
        """
        return np.random.randint(-self.eta, self.eta + 1, self.n).tolist()

    def generate_keys(self):
        """
        执行密钥生成流程。
        
        返回:
            pk (Public Key): {'rho': bytes, 't1': list}
            sk (Secret Key): {'rho': bytes, 's1': list, 's2': list, 't0': list}
            
        注意: 在完整实现中，sk 还应包含公钥的哈希 tr 和伪随机密钥 K
        """
        # 1. 生成公共种子 rho
        rho = secrets.token_bytes(32)
        
        # 2. 扩展生成矩阵 A
        A = self.expand_a(rho)
        
        # 3. 采样私钥向量 s1 (长度 L) 和 s2 (长度 K)
        s1 = [self.sample_secret_poly() for _ in range(self.l)]
        s2 = [self.sample_secret_poly() for _ in range(self.k)]
        
        # 4. 计算 t = A @ s1 + s2
        # 这是一个矩阵向量乘法，元素运算为多项式乘法
        t = []
        for i in range(self.k):
            # 计算 A 的第 i 行与 s1 的点积
            row_res = [0] * self.n
            for j in range(self.l):
                # 多项式乘法
                prod = polymul_rq(A[i][j], s1[j])
                # 多项式加法 (逐系数模加)
                row_res = [(c1 + c2) % self.q for c1, c2 in zip(row_res, prod)]
            # 加上 s2[i]
            row_res = [(c1 + c2) % self.q for c1, c2 in zip(row_res, s2[i])]
            t.append(row_res)

class KeyTool:
    """
    [纯软件实现] 抗量子密钥生成工具
    基于 Module-LWE (Learning With Errors) 困难问题
    """
    
    @staticmethod
    def generate_keypair():
        """
        生成本地身份密钥对 (sk, pk)
        """
        print("[KeyTool] 正在初始化格参数 (N={}, Q={})...".format(Config.N, Config.Q))
        
        # 参数引用
        N, Q = Config.N, Config.Q
        K, L = Config.K, Config.L
        ETA = Config.ETA

        # 1. 生成公共种子 (Public Seed) - 32 Bytes
        # 这是一个随机数，包含在公钥里。验证者用它重建矩阵 A。
        public_seed = secrets.token_hex(32)
        
        # 2. 扩展生成公共矩阵 A (K x L)
        # A 是完全由种子决定的，不需要存储在私钥里
        A = LatticeUtils.gen_matrix(public_seed, K, L, N, Q)
        
        # 3. 采样私钥向量 s (L x 1) 和 误差向量 e (K x 1)
        # 这里的元素是“多项式”，不是数字
        print("[KeyTool] 采样高熵私钥向量与误差项...")
        s = [LatticeUtils.sample_poly_centered(N, ETA) for _ in range(L)]
        e = [LatticeUtils.sample_poly_centered(N, ETA) for _ in range(K)]
        
        # 4. 计算 LWE 公钥 t = A * s + e
        # 这是一个 矩阵(KxL) * 向量(Lx1) + 向量(Kx1) 的运算
        print("[KeyTool] 执行 LWE 矩阵运算 (t = As + e)...")
        t = [] # 结果是一个长度为 K 的多项式向量
        
        for i in range(K):
            # 计算 A 的第 i 行与 s 的点积
            # 使用Python内置的int类型，而不是numpy类型
            row_poly_sum = [0] * N
            
            for j in range(L):
                poly_a = A[i][j]
                poly_s = s[j]
                # 多项式乘法: a(x) * s(x)
                product = LatticeUtils.polymul(poly_a, poly_s, Q, N)
                # 对乘积进行中心化处理
                centered_product = [LatticeUtils.center_mod(c, Q) for c in product]
                # 累加并进行中心化处理
                row_poly_sum = [(r + c) % Q for r, c in zip(row_poly_sum, centered_product)]
            
            # 加上误差 e[i] 并进行中心化处理
            # t[i] = (RowSum + e[i]) mod Q
            final_poly = [(r + c) % Q for r, c in zip(row_poly_sum, e[i])]
            # 对最终结果进行中心化处理
            centered_final_poly = [LatticeUtils.center_mod(c, Q) for c in final_poly]
            t.append(centered_final_poly)
            
        # --- 构造输出结构 ---
        
        # 私钥 (.sk): 包含 s 向量，这是核心机密
        sk = {
            "version": "LWE-1.0",
            "type": "SECRET_KEY",
            "timestamp": int(time.time()),
            "public_seed": public_seed, # 需要保存种子以备签名时重建 A
            "s": s,                     # 私钥向量 (核心)
            # t 存入私钥是为了方便本地校验，非必需
            "t": t                       
        }
        
        # 公钥 (.pk): 包含 t 向量和种子
        pk = {
            "version": "LWE-1.0",
            "type": "PUBLIC_KEY",
            "timestamp": int(time.time()),
            "public_seed": public_seed, # 公开种子
            "t": t                      # 公开向量
        }
        
        return pk, sk
