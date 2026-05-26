"""
src/network/secure_channel.py
[Phase 13] 抗量子双向认证安全信道 (C10标准 - 1.5-RTT)
结合 ML-KEM-512 和 ML-DSA-44，实现3-Way Handshake + 双向抗量子签名认证
"""

import os
import struct
import hashlib
import logging
from enum import IntEnum
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.crypto_lattice.encryptor import KyberKEM
from src.crypto_lattice.signer import DilithiumSigner
from src.config import SigParams, KEMParams


class ChannelState(IntEnum):
    NONE = 0
    HANDSHAKING = 1
    ESTABLISHED = 2
    INIT = 0  # 新API别名
    WAIT_SERVER_RESP = 1  
    WAIT_CLIENT_FINISHED = 3  
    CLOSED = 4  

class HandshakeMsgType(IntEnum):
    CLIENT_HELLO = 1  
    SERVER_RESP = 2  
    CLIENT_FINISHED = 3 
    APP_DATA = 4  

class HandshakeAuthError(Exception):
    pass


class SecureChannel:
    def __init__(self, role: str = None, is_server: bool = None, my_identity_keypair: dict = None, 
                 my_pk=None, my_sk=None, peer_fp: str = None, expected_peer_fp: str = None):
        self.legacy_mode = (is_server is None and role is not None) or (my_identity_keypair is None and my_pk is not None)
        if is_server is not None:
            self.is_server = is_server
        elif role is not None:
            self.is_server = (role == "server")
        else:
            self.is_server = False
        if my_identity_keypair is not None:
            self.my_pk = my_identity_keypair.get("pk", None)
            self.my_sk = my_identity_keypair.get("sk", None)
        else:
            self.my_pk = my_pk
            self.my_sk = my_sk
        self.expected_peer_fp = expected_peer_fp if expected_peer_fp is not None else peer_fp

        if self.legacy_mode and role is not None:
            if role == 'client' and self.expected_peer_fp is None:
                raise ValueError("Client requires 'peer_fp' (fingerprint) to verify the server.")
            if role == 'server' and (self.my_sk is None or self.my_pk is None):
                raise ValueError("Server requires both 'my_sk' and 'my_pk' to sign and attach to the response.")

        self.state = ChannelState.NONE
        self.session_key = None
        self.aesgcm = None
        self.aes_gcm = None 
        self.remote_pk = None
        self.remote_node_id = None
        
        self.role = "server" if self.is_server else "client"
        self.temp_sk = None
        
        self.transcript = b""
        
        self.send_packet_callback = None
        
        self.app_data_callback = None

    def set_send_callback(self, callback):
        self.send_packet_callback = callback


    def initiate_handshake(self) -> bytes:
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
        self.aesgcm = AESGCM(self.session_key)
        self.aes_gcm = self.aesgcm
        self.state = ChannelState.ESTABLISHED
        print(f"[SecureChannel]    ✓ 安全通道已建立!")
        
        print(f"[SecureChannel] 4. 附加服务端公钥到响应...")
        import hashlib
        my_fp = hashlib.sha256(self.my_pk).hexdigest()[:16]
        print(f"[SecureChannel]    - 服务端公钥长度: {len(self.my_pk)} 字节")
        print(f"[SecureChannel]    - 服务端公钥指纹: {my_fp}")
        
        response = ciphertext + signature + self.my_pk
        print(f"[SecureChannel] ✓ 握手响应准备完成，总长度: {len(response)} 字节")
        
        return response

    def handle_handshake_response(self, payload: bytes):
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
        print(f"[SecureChannel]    - 期望指纹: {self.expected_peer_fp}")
        print(f"[SecureChannel]    - 实际指纹: {actual_fp}")
        
        if self.expected_peer_fp and actual_fp != self.expected_peer_fp:
            self.state = ChannelState.NONE
            print(f"[SecureChannel]    ✗ 指纹不匹配! MITM 攻击被阻止!")
            raise ValueError(f"Security Alert: Server PK fingerprint mismatch! MITM attack blocked.")
        print(f"[SecureChannel]    ✓ 指纹验证通过")
        
        print(f"[SecureChannel] 3. 验证 Dilithium 签名...")
        if not DilithiumSigner.verify(server_pk, ciphertext, signature):
            self.state = ChannelState.NONE
            print(f"[SecureChannel]    ✗ 签名验证失败! 可能是 MITM 攻击!")
            raise ValueError("Security Alert: Server signature verification failed! Possible MITM attack.")
        print(f"[SecureChannel]    ✓ 签名验证通过")
            
        print(f"[SecureChannel] 4. 解封装共享密钥...")
        shared_secret = KyberKEM.decapsulate(ciphertext, self.temp_sk)
        print(f"[SecureChannel]    ✓ 共享密钥长度: {len(shared_secret)} 字节")
        
        print(f"[SecureChannel] 5. 建立加密通道...")
        self.session_key = shared_secret
        self.aesgcm = AESGCM(self.session_key)
        self.aes_gcm = self.aesgcm
        self.state = ChannelState.ESTABLISHED
        self.temp_sk = None 
        print(f"[SecureChannel]    ✓ 安全通道已建立!")

    def encrypt_payload(self, plaintext: bytes) -> bytes:
        if self.state != ChannelState.ESTABLISHED: 
            raise RuntimeError("Secure channel not established.")
        nonce = os.urandom(12)
        return nonce + self.aesgcm.encrypt(nonce, plaintext, None)

    def decrypt_payload(self, payload: bytes) -> bytes:
        if self.state != ChannelState.ESTABLISHED: 
            raise RuntimeError("Secure channel not established.")
        if len(payload) < 28: 
            raise ValueError("Invalid encrypted payload size (too small).")
        nonce = payload[:12]
        ciphertext = payload[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None)
    
    def start_client_handshake(self):
        if self.is_server:
            raise RuntimeError("只有客户端可以发起 Handshake")
            
        self.kem_pk, self.kem_sk = KyberKEM.generate_keypair()
        self.transcript += self.kem_pk
        
        packet = struct.pack("!B", HandshakeMsgType.CLIENT_HELLO.value) + self.kem_pk
        self.state = ChannelState.WAIT_SERVER_RESP
        self._send_raw(packet)
        logging.info("[Channel] (Step 1) Client Hello 已发送，等待服务端响应...")

    def feed_data(self, data: bytes):
        if len(data) < 1:
            return
            
        msg_type = data[0]
        payload = data[1:]

        try:
            if msg_type == HandshakeMsgType.CLIENT_HELLO.value and self.is_server:
                self._handle_client_hello(payload)
            elif msg_type == HandshakeMsgType.SERVER_RESP.value and not self.is_server:
                self._handle_server_resp(payload)
            elif msg_type == HandshakeMsgType.CLIENT_FINISHED.value and self.is_server:
                self._handle_client_finished(payload)
            elif msg_type == HandshakeMsgType.APP_DATA.value:
                if self.state != ChannelState.ESTABLISHED:
                    logging.warning("[Channel] 拦截到越权应用层数据，信道未完成双向认证！")
                    return
                self._handle_app_data(payload)
            else:
                logging.warning(f"[Channel] 收到非法或不符合当前状态的信令类型: {msg_type}")
        except HandshakeAuthError as e:
            logging.error(f"[Channel-Security] 双向认证彻底失败，熔断连接: {e}")
            self.close()
        except Exception as e:
            logging.error(f"[Channel] 报文解析异常: {e}")
            self.close()

    def _handle_client_hello(self, pk_kem: bytes):
        if self.state != ChannelState.INIT:
            return
            
        self.transcript += pk_kem
        
        ciphertext, shared_secret = KyberKEM.encapsulate(pk_kem)
        self.session_key = shared_secret
        self.aesgcm = AESGCM(self.session_key)
        
        signature = DilithiumSigner.sign(self.my_sk, ciphertext)
        
        self.transcript += ciphertext + signature + self.my_pk
        
        payload = ciphertext + signature + self.my_pk
        packet = struct.pack("!B", HandshakeMsgType.SERVER_RESP.value) + payload
        
        self._last_server_payload = payload
        
        self.state = ChannelState.WAIT_CLIENT_FINISHED
        self._send_raw(packet)
        logging.info("[Channel] (Step 2) Server Response 已发送，等待客户端提供 Finished 证明...")

    def _handle_server_resp(self, payload: bytes):
        if self.state != ChannelState.WAIT_SERVER_RESP:
            return
            
        C_LEN = KEMParams.CT_SIZE
        SIG_LEN = SigParams.SIG_SIZE
        
        ciphertext = payload[:C_LEN]
        server_sig = payload[C_LEN:C_LEN+SIG_LEN]
        server_pk = payload[C_LEN+SIG_LEN:]
        
        server_fp = hashlib.sha256(server_pk).hexdigest()[:16]
        if self.expected_peer_fp and server_fp != self.expected_peer_fp:
            raise HandshakeAuthError(f"服务端指纹不匹配！期望 {self.expected_peer_fp}，实际 {server_fp}")
            
        if not DilithiumSigner.verify(server_pk, ciphertext, server_sig):
            raise HandshakeAuthError("服务端抗量子签名伪造！")
            
        self.session_key = KyberKEM.decapsulate(ciphertext, self.kem_sk)
        self.aesgcm = AESGCM(self.session_key)
        
        self.transcript += ciphertext + server_sig + server_pk
        transcript_hash = hashlib.sha256(self.transcript).digest()
        
        client_sig = DilithiumSigner.sign(self.my_sk, transcript_hash)
        
        auth_token = self.my_pk + client_sig
        nonce = os.urandom(12)
        encrypted_token = self.aesgcm.encrypt(nonce, auth_token, associated_data=None)
        
        packet = struct.pack("!B", HandshakeMsgType.CLIENT_FINISHED.value) + nonce + encrypted_token
        self.state = ChannelState.ESTABLISHED
        
        self.remote_pk = server_pk
        self.remote_node_id = server_fp
        
        self._send_raw(packet)
        logging.info("[Channel] (Step 3) 客户端已验证服务端，Client Finished 密文已发送。信道就绪。")

    def _handle_client_finished(self, payload: bytes):
        if self.state != ChannelState.WAIT_CLIENT_FINISHED:
            return
            
        nonce = payload[:12]
        encrypted_token = payload[12:]
        
        try:
            auth_token = self.aesgcm.decrypt(nonce, encrypted_token, associated_data=None)
            
            PK_LEN = SigParams.PK_SIZE
            client_pk = auth_token[:PK_LEN]
            client_sig = auth_token[PK_LEN:]
            
            transcript_hash = hashlib.sha256(self.transcript).digest()
            
            if not DilithiumSigner.verify(client_pk, transcript_hash, client_sig):
                raise HandshakeAuthError("客户端抗量子签名验证失败！身份不可信。")
                
            self.remote_pk = client_pk
            self.remote_node_id = hashlib.sha256(client_pk).hexdigest()[:16]
            self.state = ChannelState.ESTABLISHED
            
            logging.info(f"[Channel] (Step 4) 双向认证成功！真实的客户端节点已锚定: {self.remote_node_id}")
        except Exception as e:
            raise HandshakeAuthError(f"Client Finished 解密或验签失败: {e}")

    def encrypt_and_send(self, plaintext: bytes):
        if self.state != ChannelState.ESTABLISHED:
            logging.error("[Channel] 拒绝发送数据：信道未建立完全。")
            return
            
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data=None)
        packet = struct.pack("!B", HandshakeMsgType.APP_DATA.value) + nonce + ciphertext
        self._send_raw(packet)

    def _handle_app_data(self, payload: bytes):
        nonce = payload[:12]
        ciphertext = payload[12:]
        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            if hasattr(self, 'app_data_callback') and self.app_data_callback:
                self.app_data_callback(self.remote_node_id, plaintext)
        except Exception as e:
            logging.warning(f"[Channel] 业务数据解密失败 (AES-GCM Tag Error): {e}")

    def _send_raw(self, data: bytes):
        if self.send_packet_callback:
            self.send_packet_callback(data)

    def close(self):
        self.state = ChannelState.CLOSED
        self.session_key = b""
        self.transcript = b""
        if self.aesgcm:
            del self.aesgcm
            self.aesgcm = None
            self.aes_gcm = None
