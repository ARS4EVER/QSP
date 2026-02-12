"""
Module 1: Key Generation (Fixed)
文件路径: src/crypto_lattice/keygen.py

负责生成 LTSS 系统的公私钥对。
[修复说明]
1. 统一使用 LatticeUtils.gen_matrix (SHAKE-128) 生成矩阵 A，解决了与 Encryptor 的数学不一致问题。
2. 密钥字典增加了 'public_seed' 和 's' 字段别名，解决了 KeyError 问题。
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
    """
    def __init__(self):
        self.k = Config.K
        self.l = Config.L
        self.q = Config.Q
        self.eta = Config.ETA
        self.n = Config.N

    def expand_a(self, seed):
        """
        [关键修复] 使用与 Encryptor/Signer 一致的 SHAKE-128 生成矩阵 A
        seed: bytes
        """
        # LatticeUtils.gen_matrix 期望 hex 字符串
        return LatticeUtils.gen_matrix(seed.hex(), self.k, self.l, self.n, self.q)

    def generate_party_key(self, rho):
        """
        为单个参与者生成密钥对 (s_i, t_i)
        公钥 t_i = A * s1_i + s2_i
        """
        # 1. 获取矩阵 A (现在与系统其他部分一致了)
        A = self.expand_a(rho)
        
        # 2. 采样私钥向量 s1 (L维) 和 误差向量 s2 (K维)
        s1 = [np.random.randint(-self.eta, self.eta + 1, self.n).tolist() for _ in range(self.l)]
        s2 = [np.random.randint(-self.eta, self.eta + 1, self.n).tolist() for _ in range(self.k)]
        
        # 3. 计算公钥 t = A * s1 + s2
        t = []
        for i in range(self.k):
            row_res = [0] * self.n
            for j in range(self.l):
                prod = polymul_rq(A[i][j], s1[j])
                # 中心化累加
                centered_prod = [LatticeUtils.center_mod(c, self.q) for c in prod]
                for m in range(self.n):
                    row_res[m] += centered_prod[m]
            # 加上误差 s2
            t.append([(c + e) % self.q for c, e in zip(row_res, s2[i])])
            
        # [关键修复] 添加别名以兼容 Encryptor/Decryptor
        # Encryptor 需要 'public_seed' 和 's'
        sk = {
            'rho': rho,
            'public_seed': rho, # 兼容别名
            's1': s1,
            's': s1,            # 兼容别名 (用于解密)
            's2': s2 
        }
        
        pk = {
            'rho': rho,
            'public_seed': rho, # 兼容别名
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
        T = [[0]*self.n for _ in range(self.k)]
        for p in party_keys:
            t_i = p['pk']['t']
            for k in range(self.k):
                for idx in range(self.n):
                    T[k][idx] = (T[k][idx] + t_i[k][idx]) % self.q
                
        # 构造并保存
        group_pk_to_save = {'rho': rho.hex(), 'public_seed': rho.hex(), 'T': T}
        
        timestamp = int(time.time())
        # 确保目录存在
        os.makedirs(Config.KEYS_DIR, exist_ok=True)
        
        # 保存各方密钥 (JSON化: bytes -> hex)
        for i, p in enumerate(party_keys):
            pk = p['pk']
            sk = p['sk']
            
            pk_to_save = {
                'rho': pk['rho'].hex(),
                'public_seed': pk['rho'].hex(),
                't': pk['t']
            }
            
            sk_to_save = {
                'rho': sk['rho'].hex(),
                'public_seed': sk['rho'].hex(),
                's1': sk['s1'],
                's': sk['s1'], 
                's2': sk['s2']
            }
            
            pk_filename = os.path.join(Config.KEYS_DIR, f'party_{i}_public_key.json') # 简化文件名
            sk_filename = os.path.join(Config.KEYS_DIR, f'party_{i}_secret_key.json')
            
            with open(pk_filename, 'w') as f:
                json.dump(pk_to_save, f, indent=2)
            
            with open(sk_filename, 'w') as f:
                json.dump(sk_to_save, f, indent=2)

            # 同时保存简单的 .pk .sk 格式供 lock_asset 使用
            simple_pk_name = os.path.join(Config.KEYS_DIR, f"{i+1}.pk")
            simple_sk_name = os.path.join(Config.KEYS_DIR, f"{i+1}.sk")
            with open(simple_pk_name, 'w') as f:
                json.dump(pk_to_save, f)
            with open(simple_sk_name, 'w') as f:
                json.dump(sk_to_save, f)
        
        print(f"[KeyGen] 密钥已重新生成。请务必删除旧的 distributed_assets 目录并重新运行 lock_asset。")
        return None, party_keys

# 兼容旧代码的辅助工具类
class KeyTool:
    @staticmethod
    def generate_keypair():
        kg = KeyGenerator()
        rho = secrets.token_bytes(32)
        pk, sk = kg.generate_party_key(rho)
        
        # 转换字节类型为十六进制字符串，确保 JSON 可序列化
        pk_json = {
            'rho': pk['rho'].hex(),
            'public_seed': pk['public_seed'].hex(),
            't': pk['t']
        }
        
        sk_json = {
            'rho': sk['rho'].hex(),
            'public_seed': sk['public_seed'].hex(),
            's1': sk['s1'],
            's': sk['s'],
            's2': sk['s2']
        }
        
        return pk_json, sk_json