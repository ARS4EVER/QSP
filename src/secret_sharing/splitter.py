import os
from typing import List, Tuple
from .gf256 import gf_mul


class SecretSplitter:
    @classmethod
    def split_secret(cls, secret: bytes, t: int, n: int) -> List[Tuple[int, bytes]]:
        shares = [bytearray(len(secret)) for _ in range(n)]
        
        for byte_idx, byte_val in enumerate(secret):
            coeffs = [byte_val] + [os.urandom(1)[0] for _ in range(t - 1)]
            for i in range(1, n + 1):
                val = 0
                for c in reversed(coeffs):
                    val = gf_mul(val, i) ^ c
                shares[i-1][byte_idx] = val
                
        return [(i + 1, bytes(shares[i])) for i in range(n)]
