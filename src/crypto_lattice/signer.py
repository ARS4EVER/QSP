from .wrapper import LatticeWrapper


class DilithiumSigner:
    """
    Dilithium 签名器封装
    
    提供简化的签名/验证接口
    """
    
    @staticmethod
    def sign(sk: bytes, message: bytes) -> bytes:
        """使用私钥签名"""
        return LatticeWrapper.sign_message(sk, message)

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        """验证签名"""
        return LatticeWrapper.verify_signature(pk, message, signature)
