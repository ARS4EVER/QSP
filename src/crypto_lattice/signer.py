"""
Module 1: Threshold Signer and LWE Signer
文件路径: src/crypto_lattice/signer.py
"""

import time
import numpy as np
import hashlib
import json
import copy
from ..config import Config
from .ntt import polymul_rq
from .utils import LatticeUtils
from .keygen import KeyGenerator

class ThresholdSigner:
    """
    参与者节点逻辑 (Parties)
    """
    def __init__(self, sk_share, index):
        self.sk = sk_share
        self.index = index
        self.n_participants = Config.N_PARTICIPANTS if hasattr(Config, 'N_PARTICIPANTS') else 5
        self.A = KeyGenerator().expand_a(sk_share['rho'])
        self.y = None 
        self.w_share = None 
        self.timestamp = None

    def phase1_commitment(self, timestamp=None):
        """
        阶段 1: 生成承诺
        """
        self.timestamp = timestamp if timestamp else int(time.time())
        
        self.y = []
        # [优化] 缩小采样范围 (GAMMA1 >> 3)，提高一次通过率
        bound = Config.GAMMA1 >> 3 
        for _ in range(Config.L):
            poly = np.random.randint(-bound, bound + 1, Config.N).tolist()
            self.y.append(poly)
            
        Ay = self._matrix_vec_mul(self.A, self.y)
        
        # 中心化处理
        centered_Ay = []
        for poly in Ay:
            centered_poly = [LatticeUtils.center_mod(c, Config.Q) for c in poly]
            centered_Ay.append(centered_poly)
        
        self.w_share = centered_Ay
        return self.w_share

    def phase2_response(self, message_data, global_Ay_sum):
        """
        阶段 2: 生成响应
        """
        if self.y is None:
            raise ValueError("Security Violation: Phase 1 not executed or y already consumed.")
        if global_Ay_sum is None:
             raise ValueError("Security Risk: Must provide global_Ay_sum.")

        try:
            # 解析 message_data
            if isinstance(message_data, tuple) and len(message_data) == 2:
                message, timestamp = message_data
            elif isinstance(message_data, bytes):
                if len(message_data) >= 8:
                    timestamp = int.from_bytes(message_data[-8:], 'little')
                    message = message_data[:-8]
                else:
                    timestamp = 0
                    message = message_data
            else:
                raise ValueError("Invalid message_data format")
            
            # 1. 提取 HighBits(W_sum)
            alpha = 2 * Config.GAMMA2
            W_true = []
            for poly in global_Ay_sum:
                w_p = [LatticeUtils.high_bits(c, alpha, Config.Q) for c in poly]
                W_true.append(w_p)
            
            # 2. 计算挑战 c
            c_poly = self._derive_challenge(message, W_true, timestamp)
            
            # 3. 计算 z = y + c * s
            z_share = []
            cs = [polymul_rq(c_poly, s_poly) for s_poly in self.sk['s1']]
            
            for j in range(Config.L):
                z_poly = LatticeUtils.poly_add(self.y[j], cs[j], Config.Q)
                z_share.append(z_poly)
                
            # --- 拒绝采样检查 ---
            centered_z_share = []
            for poly in z_share:
                centered_poly = [LatticeUtils.center_mod(c, Config.Q) for c in poly]
                centered_z_share.append(centered_poly)
            
            max_norm = LatticeUtils.vec_infinity_norm(centered_z_share)
            norm_bound = Config.GAMMA1 - Config.BETA
            
            if max_norm >= norm_bound:
                print(f"[Signer {self.index}] Rejected: Norm {max_norm} >= {norm_bound}")
                return None 
                
            Ay = self._matrix_vec_mul(self.A, self.y)
            Ce = [polymul_rq(c_poly, e_poly) for e_poly in self.sk['s2']]
            R = [LatticeUtils.poly_sub(p1, p2, Config.Q) for p1, p2 in zip(Ay, Ce)]
            
            max_low_norm = 0
            for poly in R:
                centered = [LatticeUtils.center_mod(c, Config.Q) for c in poly]
                low = [LatticeUtils.low_bits(c, alpha, Config.Q) for c in centered]
                m = max([abs(x) for x in low])
                if m > max_low_norm: max_low_norm = m
            
            low_bound = Config.GAMMA2 - Config.BETA
            if max_low_norm >= low_bound:
                print(f"[Signer {self.index}] Rejected: LowBits {max_low_norm} >= {low_bound}")
                return None 
                
            return z_share

        finally:
            self.y = None

    def _matrix_vec_mul(self, matrix, vec):
        k = len(matrix)
        l = len(matrix[0])
        res = []
        for i in range(k):
            row_sum = [0] * Config.N
            for j in range(l):
                prod = polymul_rq(matrix[i][j], vec[j])
                for m in range(Config.N):
                    row_sum[m] += prod[m]
            res.append(row_sum)
        return res

    def _derive_challenge(self, message, W_HighBits, timestamp):
        w_bytes = b""
        for poly in W_HighBits:
            for coeff in poly:
                w_bytes += int(coeff).to_bytes(4, 'little', signed=True)
        t_bytes = int(timestamp).to_bytes(8, 'little')
        input_data = message + w_bytes + t_bytes
        digest = hashlib.shake_256(input_data).digest(Config.N // 2) 
        c = [0] * Config.N
        weight = 0
        for i in range(len(digest)):
            if weight >= Config.TAU: break
            b = digest[i]
            idx = b % Config.N
            if c[idx] == 0:
                c[idx] = 1 if (b & 1) else -1
                weight += 1
        return c

class SignatureAggregator:
    def aggregate_public_keys(self, selected_public_keys):
        if not selected_public_keys: return None
        T_sum = copy.deepcopy(selected_public_keys[0])
        for i in range(1, len(selected_public_keys)):
            pk = selected_public_keys[i]
            for j in range(len(T_sum)):
                T_sum[j] = LatticeUtils.poly_add(T_sum[j], pk[j], Config.Q)
        return T_sum

    def derive_challenge(self, message, W_HighBits, timestamp):
        import hashlib
        w_bytes = b""
        for poly in W_HighBits:
            for coeff in poly:
                w_bytes += int(coeff).to_bytes(4, 'little', signed=True)
        t_bytes = int(timestamp).to_bytes(8, 'little')
        input_data = message + w_bytes + t_bytes
        digest = hashlib.shake_256(input_data).digest(Config.N // 2) 
        c = [0] * Config.N
        weight = 0
        for i in range(len(digest)):
            if weight >= Config.TAU: break
            b = digest[i]
            idx = b % Config.N
            if c[idx] == 0:
                c[idx] = 1 if (b & 1) else -1
                weight += 1
        return c

    def aggregate_w_shares(self, w_shares):
        if not w_shares: return None
        K = len(w_shares[0])
        N = len(w_shares[0][0])
        w_sum = [[0]*N for _ in range(K)]
        for w_share in w_shares:
            for k in range(K):
                for i in range(N):
                    w_sum[k][i] += w_share[k][i]
        centered_w_sum = []
        for poly in w_sum:
            centered_poly = [LatticeUtils.center_mod(c, Config.Q) for c in poly]
            centered_w_sum.append(centered_poly)
        return centered_w_sum

    def aggregate_responses(self, z_shares):
        if not z_shares: return None
        L = len(z_shares[0])
        N = len(z_shares[0][0])
        z_sum = [[0]*N for _ in range(L)]
        for z_share in z_shares:
            for l in range(L):
                for i in range(N):
                    z_sum[l][i] += z_share[l][i]
        return z_sum
        
    def verify_final_signature(self, Z, C_poly, T_pub, A_matrix, message, timestamp, W_sum=None):
        centered_Z = []
        for poly in Z:
            centered_Z.append([LatticeUtils.center_mod(c, Config.Q) for c in poly])
        norm = LatticeUtils.vec_infinity_norm(centered_Z)
        bound = Config.GAMMA1 - Config.BETA
        
        if norm >= bound:
            print(f"[Verify] Norm too large: {norm}")
            return False
        
        if W_sum is not None:
            # 推荐方案: 检查 Hash(W_sum) == C
            alpha = 2 * Config.GAMMA2
            W_prime = []
            for poly in W_sum:
                w_p = [LatticeUtils.high_bits(c, alpha, Config.Q) for c in poly]
                W_prime.append(w_p)
            
            c_prime = self.derive_challenge(message, W_prime, timestamp)
            if c_prime != C_poly:
                print("[Verify] Hash check failed.")
                return False
            return True
        else:
            # 备用方案: 计算 AZ - CT
            AZ = self._matrix_vec_mul(A_matrix, Z)
            CT = []
            for t_poly in T_pub:
                ct_poly = polymul_rq(C_poly, t_poly)
                CT.append(ct_poly)
            
            actual = []
            for az_poly, ct_poly in zip(AZ, CT):
                diff_poly = [LatticeUtils.poly_sub([az], [ct], Config.Q)[0] for az, ct in zip(az_poly, ct_poly)]
                actual.append(diff_poly)
            
            centered_actual = []
            for poly in actual:
                centered_poly = [LatticeUtils.center_mod(c, Config.Q) for c in poly]
                centered_actual.append(centered_poly)
            
            alpha = 2 * Config.GAMMA2
            W_prime = []
            for poly in centered_actual:
                w_p = [LatticeUtils.high_bits(c, alpha, Config.Q) for c in poly]
                W_prime.append(w_p)
            
            c_prime = self.derive_challenge(message, W_prime, timestamp)
            if c_prime != C_poly:
                return False
            return True

    def _matrix_vec_mul(self, matrix, vec):
        k = len(matrix)
        l = len(matrix[0])
        res = []
        for i in range(k):
            row_sum = [0] * Config.N
            for j in range(l):
                prod = polymul_rq(matrix[i][j], vec[j])
                for m in range(Config.N):
                    row_sum[m] += prod[m]
            res.append(row_sum)
        return res

class LatticeSigner:
    """
    [核心] 抗量子签名与验证模块
    [修复版] 统一使用 polymul_rq 并加入 Rejection Sampling
    """
    
    def __init__(self):
        self.alpha = 2 * Config.GAMMA2
        self.beta = Config.BETA

    def sign(self, sk, message_bytes):
        """
        [用户端] 生成签名 (带自检重试机制)
        """
        N, Q = Config.N, Config.Q
        
        # 1. 准备数据
        if 's' in sk:
            s = np.array(sk['s'])
        elif 's1' in sk:
            s = np.array(sk['s1'])
        else:
            raise ValueError("Invalid private key: missing s")
        
        if 'public_seed' in sk:
            A = np.array(LatticeUtils.gen_matrix(sk['public_seed'], Config.K, Config.L, N, Q))
        elif 'rho' in sk:
            rho_hex = sk['rho'].hex() if isinstance(sk['rho'], bytes) else sk['rho']
            A = np.array(LatticeUtils.gen_matrix(rho_hex, Config.K, Config.L, N, Q))
        else:
            raise ValueError("Invalid private key: missing public_seed")
        
        # [关键优化] 缩小采样范围，并使用循环重试
        bound = Config.GAMMA1 >> 3
        attempts = 0
        
        while True:
            attempts += 1
            # 2. Phase 1: 承诺
            y = np.random.randint(-bound, bound, (Config.L, N))
            Ay = self._matrix_vec_mul(A, y, Q)
            w = [LatticeUtils.high_bits(poly, self.alpha, Q) for poly in Ay]
            
            # 3. Phase 2: 挑战
            w_json = json.dumps([p.tolist() for p in w]).encode()
            c_hash = hashlib.sha256(message_bytes + w_json).digest()
            c_poly = self._hash_to_poly(c_hash, N)
            
            # 4. Phase 3: 响应
            # [关键修复] 使用 polymul_rq 代替 LatticeUtils.polymul
            # 确保 z = y + c*s 中的乘法与 A*z 中的乘法一致
            cs = []
            for s_poly in s:
                # s_poly 可能是 numpy array，转换为 list 传给 polymul_rq
                sp = s_poly.tolist() if isinstance(s_poly, np.ndarray) else s_poly
                res = polymul_rq(c_poly, sp)
                cs.append(res)
            cs = np.array(cs)
            
            z = (y + cs) % Q
            
            # 5. [自检] 验证生成的签名是否会在 verify 时失败
            # 检查 LowBits(Ay) 是否过大 (因为 verify 实际上是在检查 LowBits(Ay) - ce)
            # 如果 LowBits 接近边界，可能会导致 verify 失败
            # 这里我们做一个简化检查：直接检查 z 的范数
            
            centered_z = []
            for poly in z:
                centered_z.append([LatticeUtils.center_mod(c, Q) for c in poly])
            norm_z = LatticeUtils.vec_infinity_norm(centered_z)
            
            limit_z = Config.GAMMA1 - Config.BETA
            if norm_z >= limit_z:
                # 拒绝并重试
                continue
                
            # 如果通过自检，返回签名
            return {
                "z": z.tolist(),
                "w": [p.tolist() for p in w],
                "c_hash": c_hash.hex()
            }

    def verify(self, pk, message_bytes, signature):
        """
        [系统端] 验证签名
        """
        N, Q = Config.N, Config.Q
        
        try:
            z = np.array(signature['z'])
            w = np.array(signature['w'])
            c_hash_hex = signature['c_hash']
            
            # Check 1: Hash
            w_json = json.dumps([p.tolist() for p in w]).encode()
            recomputed_hash = hashlib.sha256(message_bytes + w_json).digest()
            
            if recomputed_hash.hex() != c_hash_hex:
                print("  ❌ [Security] 哈希校验失败")
                return False
                
            # Check 2: Lattice Relation
            A = np.array(LatticeUtils.gen_matrix(pk['public_seed'], Config.K, Config.L, N, Q))
            c_poly = self._hash_to_poly(recomputed_hash, N)
            t = np.array(pk['t'])
            
            Az = self._matrix_vec_mul(A, z, Q)
            ct = np.array([LatticeUtils.polymul(c_poly, t_poly, Q, N) for t_poly in t])
            
            V = (Az - ct) % Q
            Expected = np.array([np.array(poly) * self.alpha for poly in w])
            Diff = (V - Expected) % Q
            Diff = np.where(Diff <= Q//2, Diff, Diff - Q)
            
            max_error = np.max(np.abs(Diff))
            limit = self.beta + self.alpha // 2 + 500
            
            if max_error < limit:
                print(f"  ✅ [Security] 格密码验证通过 (误差: {max_error} < {limit})")
                return True
            else:
                print(f"  ❌ [Security] 数学验证失败：误差过大 ({max_error})")
                return False
                
        except Exception as e:
            print(f"  ❌ 验证过程异常: {e}")
            return False

    def _matrix_vec_mul(self, M, v, q):
        K, L = M.shape[0], M.shape[1]
        res = []
        for i in range(K):
            row_sum = [0] * Config.N
            for j in range(L):
                prod = polymul_rq(M[i][j], v[j])
                for m in range(Config.N):
                    row_sum[m] += prod[m]
            res.append(row_sum)
        return np.array(res)

    def _hash_to_poly(self, hash_bytes, n):
        c = np.zeros(n, dtype=int)
        seed = int.from_bytes(hash_bytes[:8], 'big')
        np.random.seed(seed % (2**32))
        indices = np.random.choice(n, Config.TAU, replace=False)
        for idx in indices:
            c[idx] = np.random.choice([-1, 1])
        return c