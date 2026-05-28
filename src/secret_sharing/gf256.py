"""
GF(256) 伽罗瓦域运算查表实现

用于 Shamir 秘密共享方案中的有限域运算
"""

EXP_TABLE = [0] * 512
LOG_TABLE = [0] * 256


def _init_tables():
    """初始化指数表和对数表"""
    x = 1
    for i in range(255):
        EXP_TABLE[i] = x
        EXP_TABLE[i + 255] = x
        LOG_TABLE[x] = i
        x2 = (x << 1) ^ 0x11B if (x & 0x80) else (x << 1)
        x = x2 ^ x
    LOG_TABLE[0] = 0


_init_tables()


def gf_mul(a: int, b: int) -> int:
    """GF(256) 乘法"""
    if a == 0 or b == 0:
        return 0
    return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]]


def gf_div(a: int, b: int) -> int:
    """GF(256) 除法"""
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b]) % 255]
