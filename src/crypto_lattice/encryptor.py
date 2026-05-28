from .wrapper import LatticeWrapper


class KyberKEM:
    """
    Kyber KEM 密钥封装机制封装
    
    提供密钥交换所需的封装/解封装功能
    """
    
    @staticmethod
    def generate_keypair():
        """生成 Kyber 密钥对"""
        return LatticeWrapper.kem_keygen()

    @staticmethod
    def encapsulate(peer_pk: bytes):
        """
        封装：使用对方公钥加密，生成密文和共享密钥
        
        返回 (ciphertext, shared_secret)
        """
        return LatticeWrapper.kem_encapsulate(peer_pk)

    @staticmethod
    def decapsulate(ciphertext: bytes, my_sk: bytes):
        """解封装：使用本地私钥解出共享密钥"""
        return LatticeWrapper.kem_decapsulate(ciphertext, my_sk)
