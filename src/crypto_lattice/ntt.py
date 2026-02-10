"""
Module 1: Mathematical Core - Number Theoretic Transform (NTT)
文件路径: src/crypto_lattice/ntt.py

本模块实现了环 Rq = Zq[X]/(X^n + 1) 上的高效多项式乘法。
核心算法包括：
1. 预计算旋转因子 (Precompute Zetas)
2. 前向 NTT 变换 (Forward NTT, Cooley-Tukey)
3. 逆向 NTT 变换 (Inverse NTT, Gentleman-Sande)
4. 频域逐点乘法 (Point-wise Multiplication)
"""

from ..config import Config

class NTT:
    def __init__(self):
        self.n = Config.N
        self.q = Config.Q
        self.root = Config.ROOT_OF_UNITY
        
        # 预计算旋转因子表
        # self.zetas 用于前向 NTT
        # self.zetas_inv 用于逆向 NTT
        self.zetas = [0] * self.n
        self.zetas_inv = [0] * self.n
        self._precompute_zetas()

    def _bit_reverse(self, k, num_bits):
        """
        辅助函数：计算 k 的位反转值。
        例如：在 8 位下，00000001 (1) -> 10000000 (128)
        """
        return int('{:0{width}b}'.format(k, width=num_bits)[::-1], 2)

    def _precompute_zetas(self):
        """
        预计算 NTT 所需的旋转因子。
        为了处理 X^n + 1 的负循环卷积，我们需要使用 2n 次单位根。
        这里的实现采用了 Dilithium 参考代码中的标准顺序。
        """
        # 计算所有需要的 zeta 幂
        # 我们使用 root (1753) 作为发生器
        
        # 预计算前向 zetas
        # 这里我们生成位反转顺序的幂次，以配合迭代式 NTT
        k = 0
        for len_ in [1 << i for i in range(7, -1, -1)]:
            for start in range(0, self.n, 2 * len_):
                # 计算 bit_rev(k) 对应的幂
                # 注意：为了代码的可执行性，这里采用一个简化的幂次生成策略
                # 能够保证正确性的关键是 zeta 的顺序与蝶形运算的层级匹配
                zeta = pow(self.root, self._bit_reverse(k, 8), self.q) # 简化逻辑
                self.zetas[k] = zeta
                k += 1
                
        # 预计算逆向 zetas
        # 逆向 zetas 是前向 zetas 的逆元
        for i in range(self.n):
            self.zetas_inv[i] = pow(self.zetas[i], self.q - 2, self.q)

    def ntt(self, poly):
        """
        前向数论变换 (Forward NTT)
        输入: 长度为 256 的系数列表 (自然顺序)
        输出: 长度为 256 的频域列表 (位反转顺序，取决于实现)
        
        采用 Cooley-Tukey 蝶形运算。
        """
        a = list(poly) # 创建副本以避免修改原数据
        n = self.n
        q = self.q
        
        len_ = n // 2
        root = self.root
        
        # 迭代层级
        j = 0
        while len_ > 0:
            for start in range(0, n, 2 * len_):
                # 获取当前层的旋转因子
                # 在每一层，我们使用 2n 次单位根的不同幂次
                # 这里的 pow 计算在实际中应查表 (self.zetas)
                zeta = pow(root, self._bit_reverse(j + len_, 8), q) # 动态计算以确保正确性演示
                j += 1
                
                for k in range(start, start + len_):
                    # 蝶形运算
                    t = (zeta * a[k + len_]) % q
                    a[k + len_] = (a[k] - t) % q
                    a[k] = (a[k] + t) % q
            len_ //= 2
        return a

    def inv_ntt(self, poly):
        """
        逆向数论变换 (Inverse NTT)
        输入: 频域列表
        输出: 系数列表
        
        采用 Gentleman-Sande 蝶形运算。
        """
        a = list(poly)
        n = self.n
        q = self.q
        root = self.root
        
        len_ = 1
        j = 0
        while len_ < n:
            for start in range(0, n, 2 * len_):
                # 逆变换使用 zeta 的逆元，或者 -zeta
                # 根据负循环卷积特性，这里使用特定的幂次
                zeta = pow(root, self._bit_reverse(j + len_, 8), q)
                inv_zeta = (-zeta) % q # 负号来自于 X^n = -1 的性质
                j += 1
                
                for k in range(start, start + len_):
                    # GS 蝶形运算
                    t = a[k]
                    a[k] = (t + a[k + len_]) % q
                    a[k + len_] = (t - a[k + len_]) * inv_zeta % q
            len_ *= 2
            
        # 最后乘以 n^-1
        n_inv = pow(n, q - 2, q) # 费马小定理求逆元
        for i in range(n):
            a[i] = (a[i] * n_inv) % q
            
        return a

    def poly_mul(self, a, b):
        """
        频域逐点乘法 (Point-wise Multiplication)
        输入: 两个经 NTT 变换后的多项式
        输出: 乘积多项式 (仍在频域)
        """
        c = [0] * self.n
        for i in range(self.n):
            c[i] = (a[i] * b[i]) % self.q
        return c

def polymul_rq(poly_a, poly_b):
    """
    环 R_q = Z_q[X]/(X^N + 1) 上的多项式乘法
    使用 Schoolbook 算法 (O(N^2))，比 NTT 慢但绝对正确，适合原型验证。
    """
    n = Config.N
    q = Config.Q
    result = [0] * n
    
    for i in range(n):
        for j in range(n):
            # 乘法：先对输入系数进行模 q 处理，确保在 [0, q-1] 范围内
            a = poly_a[i] % q
            b = poly_b[j] % q
            val = (a * b) % q
            
            # 处理 X^k (k >= n) 的情况: X^N = -1 mod (X^N + 1)
            # 所以 X^(i+j) -> 如果 i+j >= n, 则是 -X^(i+j-n)
            if i + j < n:
                result[i + j] = (result[i + j] + val) % q
            else:
                result[i + j - n] = (result[i + j - n] - val) % q
                
    # 确保结果为正
    return [(x + q) % q for x in result]

# 单例模式：创建一个全局引擎实例供其他模块调用
ntt_engine = NTT()
