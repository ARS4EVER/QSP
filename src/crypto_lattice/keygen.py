import os
from .wrapper import LatticeWrapper


class KeyGen:
    """
    密钥生成工具
    
    生成、持久化、加载 Dilithium 签名密钥对
    """
    
    @staticmethod
    def generate_keys() -> tuple[bytes, bytes]:
        """生成新的签名密钥对"""
        return LatticeWrapper.generate_signing_keypair()

    @staticmethod
    def save_keys(pk: bytes, sk: bytes, pub_path: str, priv_path: str):
        """保存密钥对到文件"""
        os.makedirs(os.path.dirname(os.path.abspath(pub_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(priv_path)), exist_ok=True)
        with open(pub_path, 'wb') as f:
            f.write(pk)
        with open(priv_path, 'wb') as f:
            f.write(sk)

    @staticmethod
    def load_keys(pub_path: str, priv_path: str) -> tuple[bytes, bytes]:
        """从文件加载密钥对"""
        with open(pub_path, 'rb') as f:
            pk = f.read()
        with open(priv_path, 'rb') as f:
            sk = f.read()
        return pk, sk
