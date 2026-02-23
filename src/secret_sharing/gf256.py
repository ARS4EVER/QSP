"""
src/secret_sharing/gf256.py
[Phase 7] 伽罗瓦域 GF(256) 极速查表核心
用空间换时间，将多项式乘除法的时间复杂度降至 O(1)。
"""

EXP_TABLE = [0] * 512
LOG_TABLE = [0] * 256

def _init_tables():
    x = 1
    for i in range(255):
        EXP_TABLE[i] = x
        EXP_TABLE[i + 255] = x
        LOG_TABLE[x] = i
        # GF(256) 乘法基：不可约多项式 x^8 + x^4 + x^3 + x + 1 (0x11B)
        x2 = (x << 1) ^ 0x11B if (x & 0x80) else (x << 1)
        x = x2 ^ x
    LOG_TABLE[0] = 0

_init_tables()

def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0: return 0
    return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]]

def gf_div(a: int, b: int) -> int:
    if a == 0: return 0
    if b == 0: raise ZeroDivisionError("GF(256) division by zero")
    return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b]) % 255]
