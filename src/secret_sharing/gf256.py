"""
src/secret_sharing/gf256.py
[Phase 7] 伽罗瓦域 GF(256) 极速查表
"""

EXP_TABLE = [0] * 512
LOG_TABLE = [0] * 256

def _init_tables():
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
    if a == 0 or b == 0: return 0
    return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]]

def gf_div(a: int, b: int) -> int:
    if a == 0: return 0
    if b == 0: raise ZeroDivisionError("GF(256) division by zero")
    return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b]) % 255]
