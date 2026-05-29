from .wrapper import LatticeWrapper

class KyberKEM:

    @staticmethod
    def generate_keypair():
        return LatticeWrapper.kem_keygen()

    @staticmethod
    def encapsulate(peer_pk: bytes):
        return LatticeWrapper.kem_encapsulate(peer_pk)

    @staticmethod
    def decapsulate(ciphertext: bytes, my_sk: bytes):
        return LatticeWrapper.kem_decapsulate(my_sk, ciphertext)
