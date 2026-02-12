import math
from functools import reduce

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def is_coprime(num, existing_list):
    """检查 num 是否与列表中所有数互质"""
    for x in existing_list:
        if gcd(num, x) != 1:
            return False
    return True

def generate_secure_moduli(n, t, q_pixel=255):
    """
    根据论文1 (陈维启) 动态生成 CRT 模数
    约束条件: 
    1. m_1 < m_2 < ... < m_n (互质)
    2. N = prod(最小t个) > q_pixel * prod(最大t-1个)
    """
    print(f"[Math] 正在计算满足 (n={n}, t={t}) 的安全模数...")
    
    # 策略：从 257 (大于255的质数附近) 开始寻找互质数
    # 模数越小，投影越小，隐写对画质影响越小
    current_start = 257
    
    while True:
        moduli = []
        candidate = current_start
        
        # 1. 贪心寻找 n 个互质数
        while len(moduli) < n:
            if is_coprime(candidate, moduli):
                moduli.append(candidate)
            candidate += 1
            # 防止无限循环
            if candidate - current_start > 2000:
                break
        
        if len(moduli) < n:
            current_start += 10
            continue

        moduli.sort()
        
        # 2. 论文核心安全校验 (Eq. 7)
        # 恢复条件：N (最小t个积) 必须足够大以容纳秘密
        min_prod_t = reduce(lambda x, y: x * y, moduli[:t])
        
        # 安全条件：M' (最大t-1个积) * 255 必须小于 N
        # 这样保证了拥有 t-1 个份额的人无法穷举出秘密
        max_prod_t_minus_1 = reduce(lambda x, y: x * y, moduli[-(t-1):])
        
        security_bound = q_pixel * max_prod_t_minus_1
        
        if min_prod_t > security_bound:
            # 计算安全余量
            margin = min_prod_t / security_bound
            print(f"[Math] 模数生成成功: {moduli}")
            print(f"       安全系数: {margin:.2f} (须 > 1.0)")
            return moduli
        else:
            # 如果不满足，说明数太小，增大搜索起点
            current_start += 13 # 步进质数步长