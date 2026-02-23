"""
src/crypto_lattice/encryptor.py
[Paper 5] 抗量子 KEM 封装

此模块负责密钥协商，而不负责具体的数据加密。
它利用 ML-KEM-512 算法生成一个只有通信双方知道的 32字节共享密钥。
"""

from .wrapper import LatticeWrapper

class KyberKEM:
    """
    [Key Encapsulation Mechanism]
    基于 NIST ML-KEM-512 (Kyber512)
    """
    
    @staticmethod
    def generate_keypair():
        """
        [Server/Receiver Action] 生成临时 KEM 密钥对
        通常在握手开始时由服务端生成，或者作为长期身份公钥。
        
        Returns:
            pk (bytes): 公钥 (800 bytes)
            sk (bytes): 私钥 (1632 bytes)
        """
        # 调用适配器的 kem_keygen
        return LatticeWrapper.kem_keygen()

    @staticmethod
    def encapsulate(peer_pk: bytes):
        """
        [Client/Sender Action] 生成共享密钥并封装
        客户端使用服务端的公钥，生成一个共享密钥 ss 和对应的密文 ct。
        
        Args:
            peer_pk (bytes): 接收方的公钥 (800 bytes)
            
        Returns:
            ciphertext (bytes): 需通过网络发送给对方的密文 (768 bytes)
            shared_secret (bytes): 本地保留的共享密钥 (32 bytes)
        """
        # 调用适配器的 kem_encapsulate
        # 注意: 适配器已确保返回顺序为 (ciphertext, shared_secret)
        return LatticeWrapper.kem_encapsulate(peer_pk)

    @staticmethod
    def decapsulate(ciphertext: bytes, my_sk: bytes):
        """
        [Server/Receiver Action] 解开密文获取共享密钥
        服务端使用自己的私钥解密客户端发来的密文，恢复出相同的共享密钥。
        
        Args:
            ciphertext (bytes): 接收到的密文 (768 bytes)
            my_sk (bytes): 我的私钥
            
        Returns:
            shared_secret (bytes): 恢复出的共享密钥 (32 bytes)
        """
        # 调用适配器的 kem_decapsulate，参数顺序为 (sk, ciphertext)
        return LatticeWrapper.kem_decapsulate(my_sk, ciphertext)