import os

try:
    from dilithium_py.ml_dsa import ML_DSA_44
except ImportError as e:
    raise ImportError(f"无法导入 dilithium-py: {e}")

try:
    from kyber_py.ml_kem import ML_KEM_512 
except ImportError as e:
    raise ImportError(f"无法导入 kyber-py: {e}")


class LatticeWrapper:
    """
    抗量子密码学包装器
    
    封装 ML-DSA-44（签名）和 ML-KEM-512（密钥封装）两个后量子算法
    """
    
    @staticmethod
    def generate_signing_keypair() -> tuple[bytes, bytes]:
        """生成 Dilithium 签名密钥对 (pk, sk)"""
        pk, sk = ML_DSA_44.keygen()
        return pk, sk

    @staticmethod
    def sign_message(sk: bytes, message: bytes) -> bytes:
        """使用 Dilithium 私钥签名消息"""
        return ML_DSA_44.sign(sk, message)

    @staticmethod
    def verify_signature(pk: bytes, message: bytes, signature: bytes) -> bool:
        """验证 Dilithium 签名"""
        try:
            return ML_DSA_44.verify(pk, message, signature)
        except Exception:
            return False

    @staticmethod
    def kem_keygen() -> tuple[bytes, bytes]:
        """生成 Kyber KEM 密钥对 (pk, sk)"""
        pk, sk = ML_KEM_512.keygen()
        return pk, sk
        
    @staticmethod
    def kem_encapsulate(pk: bytes) -> tuple[bytes, bytes]:
        """使用对方公钥封装，生成密文和共享秘密"""
        shared_secret, ciphertext = ML_KEM_512.encaps(pk)
        return ciphertext, shared_secret
        
    @staticmethod
    def kem_decapsulate(sk: bytes, ciphertext: bytes) -> bytes:
        """使用本地私钥解封装，恢复共享秘密"""
        shared_secret = ML_KEM_512.decaps(sk, ciphertext)
        return shared_secret
