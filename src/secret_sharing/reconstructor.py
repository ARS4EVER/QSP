from typing import List, Tuple
from .gf256 import gf_mul, gf_div


class SecretReconstructor:
    """
    Shamir 秘密重建器
    
    使用 Lagrange 插值法从 t 个份额重建原始秘密
    """
    
    @classmethod
    def reconstruct(cls, shares: List[Tuple[int, bytes]]) -> bytes:
        """
        从份额列表重建秘密
        
        Args:
            shares: List[(index, share_bytes)]，至少 t 个份额
        
        Returns:
            重建的原始秘密字节数据
        """
        if not shares:
            return b""
        t = len(shares)
        secret_len = len(shares[0][1])
        secret = bytearray(secret_len)
        xs = [s[0] for s in shares]

        basis_coeffs = []
        for i, x_i in enumerate(xs):
            num, den = 1, 1
            for j, x_j in enumerate(xs):
                if i != j:
                    num = gf_mul(num, x_j)
                    den = gf_mul(den, x_i ^ x_j)  # GF(256) 中加减法就是异或
            basis_coeffs.append(gf_div(num, den))

        for byte_idx in range(secret_len):
            val = 0
            for i in range(t):
                y_i = shares[i][1][byte_idx]
                val ^= gf_mul(y_i, basis_coeffs[i])
            secret[byte_idx] = val

        return bytes(secret)
