# -*- coding: utf-8 -*-
import math
import numpy as np
from functools import reduce

def extended_gcd(a, b):
    """
    扩展欧几里得算法
    返回 (g, x, y) 使得 ax + by = g
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y

def mod_inverse(a, m):
    """
    求 a 在模 m 下的逆元
    即找到 x 使得 (a * x) % m == 1
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def get_product(numbers):
    """
    计算列表中所有数字的乘积
    使用 functools.reduce 高效计算列表元素的乘积
    """
    return reduce((lambda x, y: x * y), numbers, 1)

def batch_crt_solve(shares, moduli, m0):
    """
    向量化CRT求解器 (Vectorized CRT Solver)
    
    设计思路:
    针对图像数据的百万级像素，利用 NumPy 的广播机制和对象数组进行并行计算
    
    参数:
        shares (list of np.array): 份额列表，每个元素是一个一维数组，包含第i个分片的所有像素值
        moduli (list of int): 对应的模数列表 [m_i1, m_i2,..., m_it]
        m0 (int): 秘密模数 (LARGE_PRIME_Q)
        
    返回:
        S (np.array): 重构出的原始秘密像素数组 (uint8)
    """
    t = len(moduli)
    # 1. 计算总模数积 M' (Product of all participating moduli)
    M_prime = get_product(moduli)
    
    # 2. 预计算 CRT 权重 (Precompute Weights)
    # CRT公式: Y = Sum( a_i * M_i * inv_i ) mod M'
    # 其中 M_i = M_prime / m_i
    weights = []
    for i in range(t):
        M_i = M_prime // moduli[i]
        inv_i = mod_inverse(M_i, moduli[i])
        # 权重 w_i = M_i * inv_i
        weights.append(M_i * inv_i)
    
    # 3. 向量化累加 (Vectorized Accumulation)
    # 初始化累加器。注意：由于中间计算结果可能会非常大（超过2^64），
    # 我们显式指定 dtype=object 以利用 Python 的大整数特性，避免溢出
    sum_val = np.zeros_like(shares[0], dtype=object)
    
    for i in range(t):
        # 转换输入 shares 为 object 类型参与大数运算
        term = shares[i].astype(object) * weights[i]
        sum_val += term
        
    # 4. 模约减与秘密提取
    # Y = sum_val % M_prime (CRT 唯一解)
    # S = Y % m0 (Asmuth-Bloom 解码)
    Y = sum_val % M_prime
    S = Y % m0
    
    # 5. 类型转换
    # 确认结果在 0-255 范围内后，转回 uint8 以构建图像
    return S.astype(np.uint8)