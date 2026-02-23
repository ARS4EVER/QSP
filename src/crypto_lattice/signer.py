"""
src/crypto_lattice/signer.py
[Phase 1 Refactor] 标准抗量子签名器

放弃了复杂的门限签名（TSS）逻辑，回归纯粹的单节点标准签名。
主要用于网络通信握手阶段的身份认证，防止中间人攻击。
"""

from .wrapper import LatticeWrapper

class DilithiumSigner:
    """
    [Standard Digital Signature]
    基于 NIST ML-DSA-44 (Dilithium2) 的标准签名器
    """
    
    @staticmethod
    def sign(sk: bytes, message: bytes) -> bytes:
        """
        [Sender Action] 使用本地私钥对消息进行标准签名
        
        Args:
            sk (bytes): 发送方的完整私钥
            message (bytes): 待认证的原始消息内容
            
        Returns:
            signature (bytes): 签名结果 (Dilithium2 长度为 2420 字节)
        """
        return LatticeWrapper.sign_message(sk, message)

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        """
        [Receiver Action] 使用对方公钥验证签名
        
        Args:
            pk (bytes): 声明发送方的公钥
            message (bytes): 接收到的原始消息内容
            signature (bytes): 附加的签名字节流
            
        Returns:
            bool: 验证通过返回 True，否则返回 False
        """
        return LatticeWrapper.verify_signature(pk, message, signature)
