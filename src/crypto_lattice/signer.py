from .wrapper import LatticeWrapper

class DilithiumSigner:
    @staticmethod
    def sign(sk: bytes, message: bytes) -> bytes:
        return LatticeWrapper.sign_message(sk, message)

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        return LatticeWrapper.verify_signature(pk, message, signature)
