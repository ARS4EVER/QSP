import os
from .wrapper import LatticeWrapper

class KeyGen:
    
    @staticmethod
    def generate_keys() -> tuple[bytes, bytes]:
        return LatticeWrapper.generate_signing_keypair()

    @staticmethod
    def save_keys(pk: bytes, sk: bytes, pub_path: str, priv_path: str):
        os.makedirs(os.path.dirname(os.path.abspath(pub_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(priv_path)), exist_ok=True)
        
        with open(pub_path, 'wb') as f:
            f.write(pk)
        with open(priv_path, 'wb') as f:
            f.write(sk)

    @staticmethod
    def load_keys(pub_path: str, priv_path: str) -> tuple[bytes, bytes]:
        with open(pub_path, 'rb') as f:
            pk = f.read()
        with open(priv_path, 'rb') as f:
            sk = f.read()
        return pk, sk
