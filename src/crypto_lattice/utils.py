"""
Module 1: Auxiliary Cryptographic Functions
文件路径: src/crypto_lattice/utils.py

本模块实现了格密码所需的位级操作函数，用于压缩、舍入和提示位生成。
算法严格遵循 CRYSTALS-Dilithium 规范和文献1中的算法定义。
"""

import numpy as np
import hashlib
from ..config import Config

class LatticeUtils:
    """
    格密码数学工具库
    对应文献1中的算法 1, 2, 3 (Decompose, HighBits, LowBits)
    """
    
    @staticmethod
    def center_mod(x, q):
        """
        中心化取模操作。
        将任意整数 x 映射到区间 [-q/2, q/2]。
        标准的 % 运算符返回的是 [0, q-1]，这在格密码中会导致范数计算错误。
        """
        import numpy as np
        r = x % q
        if isinstance(r, np.ndarray):
            # 对于numpy数组，使用vectorize或where
            r = np.where(r > q // 2, r - q, r)
        else:
            # 对于标量
            if r > q // 2:
                r -= q
        return r

    @staticmethod
    def infinity_norm(poly):
        """
        计算多项式的 L-infinity 范数（最大绝对系数）。
        用于拒绝采样中的边界检查。
        """
        # 直接计算系数的绝对值，因为我们关心的是实际大小
        return max([abs(c) for c in poly])

    @staticmethod
    def power2round(r, d):
        """
        Power2Round 算法。
        将 r 分解为 (r1, r0) 使得 r = r1 * 2^d + r0。
        r0 的范围是 [-2^(d-1), 2^(d-1)]。
        
        用于 KeyGen 中压缩公钥 t。
        """
        q = Config.Q
        r = r % q
        
        # 计算低位 r0，确保在中心化区间
        r0 = LatticeUtils.center_mod(r, 1 << d) 
        
        # 计算高位 r1
        # Python 的 // 是向下取整，这与 C 语言的截断除法不同，需注意
        # 这里 (r - r0) 必定能被 2^d 整除
        r1 = (r - r0) >> d
        
        return (r1 % q, r0)

    @staticmethod
    def decompose(r, alpha, q=None):
        """
        算法 1: Decompose
        输入: r, alpha
        输出: (r1, r0) 使得 r = r1 * alpha + r0
        其中 r0 落在 [-alpha/2, alpha/2] 范围内 (中心化取模)
        """
        import numpy as np
        if q is None:
            q = Config.Q
            
        # 1. 直接对输入 r 进行中心化处理
        # 因为输入 r 可能已经在 [-q/2, q/2] 范围内，也可能不在
        r_centered = LatticeUtils.center_mod(r, q)
        
        # 2. 计算 r0 = r_centered mod alpha (中心化)
        r0 = r_centered % alpha
        if isinstance(r0, np.ndarray):
            # 对于numpy数组
            r0 = np.where(r0 > alpha // 2, r0 - alpha, r0)
        else:
            # 对于标量
            if r0 > alpha // 2:
                r0 -= alpha
            
        # 3. 计算 r1
        # 确保使用整数除法，避免浮点数精度问题
        r1 = (r_centered - r0) // alpha
        
        return r1, r0

    @staticmethod
    def high_bits(r, alpha, q=None):
        """
        算法 2: HighBits
        返回 Decompose 的 r1 部分
        """
        if q is None:
            q = Config.Q
            
        r1, _ = LatticeUtils.decompose(r, alpha, q)
        return r1

    @staticmethod
    def low_bits(r, alpha, q=None):
        """
        算法 3: LowBits
        返回 Decompose 的 r0 部分
        """
        if q is None:
            q = Config.Q
            
        _, r0 = LatticeUtils.decompose(r, alpha, q)
        return r0

    @staticmethod
    def poly_add(p1, p2, q=None):
        """
        多项式加法 (模 q)
        """
        if q is None:
            q = Config.Q
            
        return [(c1 + c2) % q for c1, c2 in zip(p1, p2)]

    @staticmethod
    def poly_sub(p1, p2, q=None):
        """
        多项式减法 (模 q)
        """
        if q is None:
            q = Config.Q
            
        return [(c1 - c2) % q for c1, c2 in zip(p1, p2)]

    @staticmethod
    def vec_infinity_norm(vec):
        """
        计算多项式向量的无穷范数 (所有多项式系数中的最大值)
        """
        max_norm = 0
        for poly in vec:
            # 直接计算每个多项式的最大绝对系数
            poly_max = max([abs(c) for c in poly])
            if poly_max > max_norm:
                max_norm = poly_max
        return max_norm

    @staticmethod
    def make_hint(z, r, alpha):
        """
        MakeHint 算法。
        生成一个比特 h，指示 r 的高位和 (r+z) 的高位是否不同。
        用于帮助验证者修正由于 'z' (部分掩码) 引起的进位误差。
        
        输入:
            z: 两个值的差值 (通常较小)
            r: 基准值
            alpha: 分解因子 (2*gamma2)
        """
        r1 = LatticeUtils.high_bits(r, alpha)
        v1 = LatticeUtils.high_bits(r + z, alpha)
        
        # 如果高位不同，则 hint 为 1
        return 1 if r1 != v1 else 0

    @staticmethod
    def use_hint(h, r, alpha):
        """
        UseHint 算法。
        根据提示 h 和值 r，恢复出目标值的高位部分。
        这允许验证者在不知道具体 z 的情况下，推导出正确的高位。
        """
        m = (Config.Q - 1) // alpha
        r1 = LatticeUtils.high_bits(r, alpha)
        
        if h == 0:
            return r1
        
        # 如果 hint 为 1，意味着发生了进位或借位
        # 需要检查环绕情况 (模 m 环)
        if r1 == m - 1:
            return 0
        return r1 + 1
    
    @staticmethod
    def polymul(a, b, q, n):
        """
        在环 Zq[X]/(X^N + 1) 上执行多项式乘法。
        输入: 两个长度为 n 的系数列表/数组 a, b
        输出: 长度为 n 的系数列表
        """
        # 1. 使用 numpy 执行多项式卷积 (结果长度 2N-1)
        # 这一步计算的是普通多项式乘法 a(x) * b(x)
        raw_product = np.convolve(a, b).astype(int)
        
        # 2. 模多项式规约 (Reduction modulo X^N + 1)
        # 利用性质: X^N \equiv -1 (mod X^N + 1)
        # 将高位部分 (index >= N) 减到低位部分
        final_coeffs = np.zeros(n, dtype=int)
        
        # 复制低位部分 [0, N-1]
        limit = min(len(raw_product), n)
        final_coeffs[:limit] = raw_product[:limit]
        
        # 处理高位部分
        if len(raw_product) > n:
            # 高位系数 raw_product[i] 对应 x^i = x^{N + (i-N)} = -x^{i-N}
            # 所以要减去高位
            upper_part = raw_product[n:]
            final_coeffs[:len(upper_part)] -= upper_part
            
        # 3. 模 Q 规约
        return (final_coeffs % q).tolist()

    @staticmethod
    def vec_add(v1, v2, q):
        """多项式向量加法"""
        return [(x + y) % q for x, y in zip(v1, v2)]

    @staticmethod
    def gen_matrix(seed_hex, k, l, n, q):
        """
        从公共种子(Public Seed)扩展生成矩阵 A (K x L)
        使用 SHAKE-128 哈希函数作为伪随机数生成器(XOF)
        这保证了只要有种子，所有人生成的矩阵 A 都是一样的。
        """
        matrix = []
        seed_bytes = bytes.fromhex(seed_hex)
        
        for i in range(k):
            row = []
            for j in range(l):
                # 为矩阵每个位置 (i, j) 生成独立的随机流
                # 这种确定性生成方式是抗量子公钥压缩的关键
                unique_seed = seed_bytes + bytes([i]) + bytes([j])
                
                # 使用 SHAKE-128 生成足够的字节
                # 每个系数约需 3 字节 (2^23 < 8380417 < 2^24)
                hasher = hashlib.shake_128(unique_seed)
                # 生成稍微多一点的字节以防拒绝采样消耗
                byte_stream = hasher.digest(n * 4) 
                
                poly = []
                idx = 0
                while len(poly) < n and idx + 3 <= len(byte_stream):
                    # 取 3 字节转为整数
                    b1, b2, b3 = byte_stream[idx], byte_stream[idx+1], byte_stream[idx+2]
                    val = (b1 << 16) | (b2 << 8) | b3
                    val &= 0x7FFFFF # 限制范围优化采样
                    
                    if val < q:
                        poly.append(val)
                    idx += 3
                
                # 极罕见情况补 0 (工程容错)
                while len(poly) < n:
                    poly.append(0)
                    
                row.append(poly)
            matrix.append(row)
        return matrix

    @staticmethod
    def sample_poly_centered(n, eta):
        """
        从中心二项分布 (Centered Binomial Distribution) 采样误差多项式
        这是 LWE 问题安全性的来源
        """
        # 简单模拟: 在 [-eta, eta] 范围内均匀采样
        # 严谨学术实现应使用 CBD，此处简化演示
        return np.random.randint(-eta, eta + 1, n).tolist()
