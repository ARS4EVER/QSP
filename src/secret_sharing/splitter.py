import os
from typing import List, Tuple
from .gf256 import gf_mul


class SecretSplitter:
    """
    Shamir 秘密分割器
    
    使用 (t, n) 阈值方案将秘密分割为 n 个份额
    任意 t 个或更多份额可重建原始秘密，少于 t 个份额无法获得任何信息
    """
    
    @classmethod
    def split_secret(cls, secret: bytes, t: int, n: int) -> List[Tuple[int, bytes]]:
        """
        将秘密分割为 n 个份额
        
        Args:
            secret: 要分割的原始字节数据
            t: 阈值，需要至少 t 个份额才能重建
            n: 总份额数量
        
        Returns:
            List[(index, share_bytes)]: n 个份额，每个份额由索引和字节数据组成
        """
        shares = [bytearray(len(secret)) for _ in range(n)]
        
        for byte_idx, byte_val in enumerate(secret):
            coeffs = [byte_val] + [os.urandom(1)[0] for _ in range(t - 1)]
            for i in range(1, n + 1):
                val = 0
                for c in reversed(coeffs):
                    val = gf_mul(val, i) ^ c
                shares[i-1][byte_idx] = val
                
        return [(i + 1, bytes(shares[i])) for i in range(n)]
