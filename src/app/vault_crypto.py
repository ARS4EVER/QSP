import os
import hmac
import hashlib
import gc
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from src.config import DATA_DIR, KEYS_DIR 


class PasswordAuthError(Exception):
    pass

class VaultCrypto:
    MAGIC_VERIFIER = b"QSP_VAULT_MAGIC_VERIFIER"

    def __init__(self, password: str, salt_path: str = None, verifier_path: str = None, vault_dir: str = None):
        self.salt = None
        self.key = None
        self.aesgcm = None
        
        if vault_dir is None and salt_path is not None and os.path.isdir(salt_path):
            vault_dir = salt_path
            salt_path = None
        
        if vault_dir is None and verifier_path is not None and os.path.isdir(verifier_path):
            vault_dir = verifier_path
            verifier_path = None
            
        if salt_path is None:
            if vault_dir is not None:
                self.salt_path = os.path.join(vault_dir, ".vault_salt")
            else:
                self.salt_path = os.path.join(KEYS_DIR, ".vault_salt")
        else:
            self.salt_path = salt_path
            
        if verifier_path is None:
            if vault_dir is not None:
                self.verifier_path = os.path.join(vault_dir, ".vault_verifier")
            else:
                self.verifier_path = os.path.join(KEYS_DIR, ".vault_verifier")
        else:
            self.verifier_path = verifier_path
            
        self.password = password.encode('utf-8')
        
        try:

            self.salt = self._get_or_create_salt()

            self.key = self._derive_key()

            self._verify_or_create_authenticator()

            self.aesgcm = AESGCM(self.key)
            
        except Exception as e:
            self.destroy_memory_traces()
            raise e

    def _atomic_write(self, filepath: str, data: bytes):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        tmp_path = filepath + ".tmp"
        
        try:
            with open(tmp_path, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            
            os.replace(tmp_path, filepath)
            
        except OSError as e:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise IOError(f"系统级 I/O 异常，原子化写盘失败，系统状态已安全回滚。详细信息: {e}")

    def destroy_memory_traces(self):
        self.password = b""
        self.key = b""
        self.salt = b""
        if self.aesgcm:
            del self.aesgcm
            self.aesgcm = None
            
        gc.collect()

    def _get_or_create_salt(self) -> bytes:
        if os.path.exists(self.salt_path):
            with open(self.salt_path, "rb") as f:
                return f.read()
        else:
            salt = os.urandom(16)
            self._atomic_write(self.salt_path, salt)
            return salt

    def _derive_key(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.password)

    def _verify_or_create_authenticator(self):
        current_mac = hmac.new(self.key, self.MAGIC_VERIFIER, hashlib.sha256).digest()

        if os.path.exists(self.verifier_path):
            with open(self.verifier_path, "rb") as f:
                stored_mac = f.read()

            if not hmac.compare_digest(current_mac, stored_mac):
                raise PasswordAuthError("本地金库主密码错误，拒绝解锁！")
        else:
            self._atomic_write(self.verifier_path, current_mac)


    
    def encrypt_data(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext_with_tag = self.aesgcm.encrypt(nonce, data, associated_data=None)
        return nonce + ciphertext_with_tag

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        if len(encrypted_data) < 28:
            raise ValueError("Encrypted data is corrupted or too short.")
            
        nonce = encrypted_data[:12]
        ciphertext_with_tag = encrypted_data[12:]
        
        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
            return plaintext
        except InvalidTag as e:
            raise InvalidTag("[VaultCrypto] 严重：密码错误或身份文件遭到篡改，拒绝解密！") from e


    def encrypt_chunk(self, chunk: bytes) -> bytes:
        return self.encrypt_data(chunk)

    def decrypt_chunk(self, encrypted_chunk: bytes) -> bytes:
        return self.decrypt_data(encrypted_chunk)
