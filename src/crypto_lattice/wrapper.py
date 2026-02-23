"""
src/crypto_lattice/wrapper.py
[Phase 1 Refactor] 标准后量子密码学高层适配器
功能: 
1. 提供标准 ML-DSA (Dilithium) API 用于节点的身份认证与数字签名。
2. 提供标准 ML-KEM (Kyber) API 用于密钥交换与加密安全通道建立。
不再暴露任何底层多项式或 NTT 数学接口，确保 100% 贴合 FIPS 标准。
"""

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
    统一的后量子密码学原语封装 (标准黑盒调用)
    """
    
    # --- ML-DSA (Dilithium2) 身份认证 API ---
    
    @staticmethod
    def generate_signing_keypair() -> tuple[bytes, bytes]:
        """
        生成 ML-DSA 签名密钥对
        Returns:
            (pk, sk): 公钥和私钥的字节流
        """
        pk, sk = ML_DSA_44.keygen()
        return pk, sk

    @staticmethod
    def sign_message(sk: bytes, message: bytes) -> bytes:
        """
        使用完整私钥对消息进行标准签名
        Args:
            sk: 签名者的完整私钥
            message: 待签名的消息内容
        Returns:
            signature: 签名结果字节流 (Dilithium2 为 2420 字节)
        """
        return ML_DSA_44.sign(sk, message)

    @staticmethod
    def verify_signature(pk: bytes, message: bytes, signature: bytes) -> bool:
        """
        验证标准签名
        Args:
            pk: 签名者的公钥
            message: 原始消息内容
            signature: 签名字节流
        Returns:
            bool: 验证通过返回 True，否则返回 False
        """
        try:
            return ML_DSA_44.verify(pk, message, signature)
        except Exception:
            return False
            
            
    # --- ML-KEM (Kyber512) 密钥交换 (KEM) API ---

    @staticmethod
    def kem_keygen() -> tuple[bytes, bytes]:
        """
        生成 ML-KEM 密钥交换密钥对
        Returns:
            (pk, sk): KEM 公钥和私钥的字节流
        """
        pk, sk = ML_KEM_512.keygen()
        return pk, sk
        
    @staticmethod
    def kem_encapsulate(pk: bytes) -> tuple[bytes, bytes]:
        """
        封装密钥 (通常由 Client 执行，使用 Server 公钥)
        Args:
            pk: 对方的 KEM 公钥
        Returns:
            (ciphertext, shared_secret): 密文和协商出的对称密钥 (Session Key)
        Note:
            kyber_py 库的 encaps 返回 (shared_secret, ciphertext)，需要调整顺序
        """
        shared_secret, ciphertext = ML_KEM_512.encaps(pk)
        return ciphertext, shared_secret
        
    @staticmethod
    def kem_decapsulate(sk: bytes, ciphertext: bytes) -> bytes:
        """
        解封装密钥 (通常由 Server 执行，使用自己的 KEM 私钥解开密文)
        Args:
            sk: 本地的 KEM 私钥
            ciphertext: 接收到的对方发来的密文
        Returns:
            shared_secret: 协商出的对称密钥 (Session Key)
        """
        shared_secret = ML_KEM_512.decaps(sk, ciphertext)
        return shared_secret
