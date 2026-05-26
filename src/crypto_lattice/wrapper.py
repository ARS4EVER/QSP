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
    
    @staticmethod
    def generate_signing_keypair() -> tuple[bytes, bytes]:
        pk, sk = ML_DSA_44.keygen()
        return pk, sk

    @staticmethod
    def sign_message(sk: bytes, message: bytes) -> bytes:
        return ML_DSA_44.sign(sk, message)

    @staticmethod
    def verify_signature(pk: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return ML_DSA_44.verify(pk, message, signature)
        except Exception:
            return False
            

    @staticmethod
    def kem_keygen() -> tuple[bytes, bytes]:
        pk, sk = ML_KEM_512.keygen()
        return pk, sk
        
    @staticmethod
    def kem_encapsulate(pk: bytes) -> tuple[bytes, bytes]:
        shared_secret, ciphertext = ML_KEM_512.encaps(pk)
        return ciphertext, shared_secret
        
    @staticmethod
    def kem_decapsulate(sk: bytes, ciphertext: bytes) -> bytes:
        shared_secret = ML_KEM_512.decaps(sk, ciphertext)
        return shared_secret
