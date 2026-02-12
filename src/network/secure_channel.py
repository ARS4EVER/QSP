# src/network/secure_channel.py

import pickle
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from src.crypto_lattice.encryptor import LatticeEncryptor
from src.crypto_lattice.signer import LatticeSigner

class SecureChannel:
    """
    安全通道管理器 (Hardened Version)
    功能:
    1. 身份认证: 基于格密码签名的握手
    2. 密钥协商: 基于 KEM 的会话密钥生成
    3. 传输加密: AES-256-GCM
    """
    
    AES_KEY_SIZE = 32
    NONCE_SIZE = 12
    TIMESTAMP_TOLERANCE = 60  # 允许 60 秒的时间误差

    def __init__(self):
        self.session_key = None
        self.peer_verified = False

    @property
    def is_established(self):
        """
        [关键新增] 检查通道是否已建立
        """
        return self.session_key is not None

    def setup_host_session_signed(self, target_pk_obj, my_sk_obj):
        """[主动方] 生成会话密钥 + 封装 + 签名 + 时间戳"""
        # 1. 生成 AES 会话密钥
        self.session_key = get_random_bytes(self.AES_KEY_SIZE)
        
        # 2. KEM 封装
        cipher_struct = LatticeEncryptor._lwe_encrypt_key(target_pk_obj, self.session_key)
        
        # 3. 构造握手载荷
        timestamp = int(time.time())
        payload = {
            "ts": timestamp,
            "kem": cipher_struct
        }
        payload_bytes = pickle.dumps(payload)
        
        # 4. 签名
        signer = LatticeSigner()
        signature = signer.sign(my_sk_obj, payload_bytes)
        
        # 5. 打包
        handshake_packet = {
            "payload": payload_bytes,
            "sig": signature
        }
        return pickle.dumps(handshake_packet)

    def setup_participant_session_verified(self, handshake_data, my_sk_obj, peer_pk_obj):
        """[被动方] 验证签名 + 验证时间戳 + 解封装"""
        try:
            packet = pickle.loads(handshake_data)
            payload_bytes = packet['payload']
            signature = packet['sig']
            
            # 1. 验证签名
            verifier = LatticeSigner()
            if not verifier.verify(peer_pk_obj, payload_bytes, signature):
                print("[SecureChannel] ⚠️ 签名验证失败")
                return False
                
            # 2. 验证时间戳
            payload = pickle.loads(payload_bytes)
            ts = payload['ts']
            now = int(time.time())
            if abs(now - ts) > self.TIMESTAMP_TOLERANCE:
                print(f"[SecureChannel] ⚠️ 时间戳过期 (Diff: {now-ts}s)")
                return False
                
            # 3. KEM 解密
            cipher_struct = payload['kem']
            session_key = LatticeEncryptor._lwe_decrypt_key(my_sk_obj, cipher_struct)
            
            if not session_key or len(session_key) != self.AES_KEY_SIZE:
                print("[SecureChannel] ⚠️ KEM 解密失败")
                return False
                
            self.session_key = session_key
            self.peer_verified = True
            return True
            
        except Exception as e:
            print(f"[SecureChannel] 握手异常: {e}")
            return False

    def encrypt_traffic(self, plaintext_bytes):
        """AES-GCM 加密"""
        if not self.session_key:
            raise ValueError("Session key not established.")
        nonce = get_random_bytes(self.NONCE_SIZE)
        cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        return nonce + tag + ciphertext

    def decrypt_traffic(self, encrypted_bytes):
        """AES-GCM 解密"""
        if not self.session_key or len(encrypted_bytes) < self.NONCE_SIZE + 16:
            return None
        try:
            nonce = encrypted_bytes[:self.NONCE_SIZE]
            tag = encrypted_bytes[self.NONCE_SIZE : self.NONCE_SIZE + 16]
            ciphertext = encrypted_bytes[self.NONCE_SIZE + 16 :]
            cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception:
            return None