# -*- coding: utf-8 -*-
"""
测试 NTT 模块的基本功能
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto_lattice.ntt import polymul_rq
from src.crypto_lattice.utils import LatticeUtils
from src.config import Config

print("测试 NTT 模块...")
print(f"配置参数: N={Config.N}, Q={Config.Q}")

# 测试多项式乘法
print("\n测试多项式乘法:")
# 创建两个简单的多项式: 1 + x 和 1 - x
poly_a = [1, 1] + [0] * (Config.N - 2)  # 1 + x
poly_b = [1, Config.Q - 1] + [0] * (Config.N - 2)  # 1 - x

result = polymul_rq(poly_a, poly_b)
print(f"(1 + x) * (1 - x) = 1 - x^2")
print(f"结果前 4 个系数: {result[:4]}")
print(f"预期结果前 4 个系数: [1, 0, Config.Q - 1, 0]")

# 测试多项式加法
print("\n测试多项式加法:")
poly_c = [1, 2, 3] + [0] * (Config.N - 3)
poly_d = [4, 5, 6] + [0] * (Config.N - 3)
add_result = LatticeUtils.poly_add(poly_c, poly_d, Config.Q)
print(f"[1, 2, 3] + [4, 5, 6] = {add_result[:4]}")

# 测试多项式减法
print("\n测试多项式减法:")
sub_result = LatticeUtils.poly_sub(poly_c, poly_d, Config.Q)
print(f"[1, 2, 3] - [4, 5, 6] = {sub_result[:4]}")

print("\n测试完成!")
