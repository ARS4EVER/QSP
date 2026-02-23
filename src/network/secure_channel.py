"""
src/network/secure_channel.py
[Phase 9] 标准抗量子安全通道 (公钥指纹验证版)
结合 ML-KEM-512 和 ML-DSA-44 实现极其安全的端到端握手。
利用指纹(Fingerprint)机制，避免邀请码携带庞大公钥。
"""

import os
import hashlib
from enum import Enum
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto_lattice.encryptor import KyberKEM
from ..crypto_lattice.signer import DilithiumSigner
from ..config import SigParams, KEMParams


class ChannelState(Enum):
    NONE = 0
    HANDSHAKING = 1
    ESTABLISHED = 2


class SecureChannel:
    def __init__(self, role='client', my_pk=None, my_sk=None, peer_fp=None):
        print(f"[SecureChannel] 初始化安全通道，角色: {role}")
        self.role = role
        self.state = ChannelState.NONE
        self.temp_sk = None
        self.session_key = None
        self.aes_gcm = None
        
        self.my_pk = my_pk
        self.my_sk = my_sk
        self.peer_fp = peer_fp
        
        if self.role == 'client' and not self.peer_fp:
            raise ValueError("Client requires 'peer_fp' (fingerprint) to verify the server.")
        if self.role == 'server' and (not self.my_sk or not self.my_pk):
            raise ValueError("Server requires both 'my_sk' and 'my_pk' to sign and attach to the response.")

    def initiate_handshake(self) -> bytes:
        """
        [Client Action] 发起握手
        Returns: 包含 Kyber 临时公钥的 payload (800 bytes)
        """
        print(f"[SecureChannel] === 客户端发起握手 ===")
        if self.role != 'client': 
            raise RuntimeError("Only client can initiate handshake.")
        
        print(f"[SecureChannel] 生成 Kyber 密钥对...")
        pk, sk = KyberKEM.generate_keypair()
        self.temp_sk = sk
        self.state = ChannelState.HANDSHAKING
        print(f"[SecureChannel] ✓ Kyber 密钥对已生成")
        print(f"[SecureChannel]   - 公钥长度: {len(pk)} 字节")
        
        return pk

    def handle_handshake_request(self, client_pk: bytes) -> bytes:
        """
        [Server Action] 处理握手请求，生成对称密钥并签名返回
        Args:
            client_pk: 接收到的 Client Kyber 公钥 (800 bytes)
        Returns: 密文 + 签名 + 服务端公钥 的 payload
        """
        print(f"[SecureChannel] === 服务端处理握手请求 ===")
        if self.role != 'server': 
            raise RuntimeError("Only server can handle handshake request.")
        if len(client_pk) != KEMParams.PK_SIZE:
            raise ValueError(f"Invalid Kyber PK size. Expected {KEMParams.PK_SIZE}, got {len(client_pk)}")
            
        print(f"[SecureChannel] 收到客户端 Kyber 公钥: {len(client_pk)} 字节")
        
        print(f"[SecureChannel] 1. 封装密钥，生成密文和共享密钥...")
        ciphertext, shared_secret = KyberKEM.encapsulate(client_pk)
        print(f"[SecureChannel]    ✓ 密文长度: {len(ciphertext)} 字节")
        print(f"[SecureChannel]    ✓ 共享密钥长度: {len(shared_secret)} 字节")
        
        print(f"[SecureChannel] 2. 用 Dilithium 私钥签名密文...")
        signature = DilithiumSigner.sign(self.my_sk, ciphertext)
        print(f"[SecureChannel]    ✓ 签名长度: {len(signature)} 字节")
        
        print(f"[SecureChannel] 3. 建立加密通道...")
        self.session_key = shared_secret
        self.aes_gcm = AESGCM(self.session_key)
        self.state = ChannelState.ESTABLISHED
        print(f"[SecureChannel]    ✓ 安全通道已建立！")
        
        print(f"[SecureChannel] 4. 附加服务端公钥到响应...")
        import hashlib
        my_fp = hashlib.sha256(self.my_pk).hexdigest()[:16]
        print(f"[SecureChannel]    - 服务端公钥长度: {len(self.my_pk)} 字节")
        print(f"[SecureChannel]    - 服务端公钥指纹: {my_fp}")
        
        response = ciphertext + signature + self.my_pk
        print(f"[SecureChannel] ✓ 握手响应准备完成，总长度: {len(response)} 字节")
        
        return response

    def handle_handshake_response(self, payload: bytes):
        """
        [Client Action] 处理握手响应，验证身份并建立加密连接
        Args:
            payload: 接收到的 Server 响应 (密文 + 签名 + 服务端公钥)
        """
        print(f"[SecureChannel] === 客户端处理握手响应 ===")
        if self.role != 'client': 
            raise RuntimeError("Only client can handle handshake response.")
        if self.state != ChannelState.HANDSHAKING: 
            raise RuntimeError("Channel is not in handshaking state.")
            
        expected_min_len = KEMParams.CT_SIZE + SigParams.SIG_SIZE
        if len(payload) <= expected_min_len:
            raise ValueError(f"Invalid response payload size. Missing server PK. Expected > {expected_min_len}, got {len(payload)}")
            
        print(f"[SecureChannel] 收到响应总长度: {len(payload)} 字节")
        
        print(f"[SecureChannel] 1. 拆解响应包...")
        ciphertext = payload[:KEMParams.CT_SIZE]
        signature = payload[KEMParams.CT_SIZE:KEMParams.CT_SIZE + SigParams.SIG_SIZE]
        server_pk = payload[KEMParams.CT_SIZE + SigParams.SIG_SIZE:]
        print(f"[SecureChannel]    - 密文: {len(ciphertext)} 字节")
        print(f"[SecureChannel]    - 签名: {len(signature)} 字节")
        print(f"[SecureChannel]    - 服务端公钥: {len(server_pk)} 字节")
        
        print(f"[SecureChannel] 2. 验证服务端公钥指纹...")
        actual_fp = hashlib.sha256(server_pk).hexdigest()[:16]
        print(f"[SecureChannel]    - 期望指纹: {self.peer_fp}")
        print(f"[SecureChannel]    - 实际指纹: {actual_fp}")
        
        if actual_fp != self.peer_fp:
            self.state = ChannelState.NONE
            print(f"[SecureChannel]    ✗ 指纹不匹配！MITM 攻击被阻止！")
            raise ValueError(f"Security Alert: Server PK fingerprint mismatch! MITM attack blocked.")
        print(f"[SecureChannel]    ✓ 指纹验证通过")
        
        print(f"[SecureChannel] 3. 验证 Dilithium 签名...")
        if not DilithiumSigner.verify(server_pk, ciphertext, signature):
            self.state = ChannelState.NONE
            print(f"[SecureChannel]    ✗ 签名验证失败！可能是 MITM 攻击！")
            raise ValueError("Security Alert: Server signature verification failed! Possible MITM attack.")
        print(f"[SecureChannel]    ✓ 签名验证通过")
            
        print(f"[SecureChannel] 4. 解封装共享密钥...")
        shared_secret = KyberKEM.decapsulate(ciphertext, self.temp_sk)
        print(f"[SecureChannel]    ✓ 共享密钥长度: {len(shared_secret)} 字节")
        
        print(f"[SecureChannel] 5. 建立加密通道...")
        self.session_key = shared_secret
        self.aes_gcm = AESGCM(self.session_key)
        self.state = ChannelState.ESTABLISHED
        self.temp_sk = None 
        print(f"[SecureChannel]    ✓ 安全通道已建立！")

    def encrypt_payload(self, plaintext: bytes) -> bytes:
        """
        加密明文数据
        Args:
            plaintext: 待加密的明文
        Returns: 加密后的密文 (包含 12 字节 nonce)
        """
        if self.state != ChannelState.ESTABLISHED: 
            raise RuntimeError("Secure channel not established.")
        nonce = os.urandom(12)
        return nonce + self.aes_gcm.encrypt(nonce, plaintext, None)

    def decrypt_payload(self, payload: bytes) -> bytes:
        """
        解密密文数据
        Args:
            payload: 待解密的密文 (包含 12 字节 nonce)
        Returns: 解密后的明文
        """
        if self.state != ChannelState.ESTABLISHED: 
            raise RuntimeError("Secure channel not established.")
        if len(payload) < 28: 
            raise ValueError("Invalid encrypted payload size (too small).")
        nonce = payload[:12]
        ciphertext = payload[12:]
        return self.aes_gcm.decrypt(nonce, ciphertext, None)
