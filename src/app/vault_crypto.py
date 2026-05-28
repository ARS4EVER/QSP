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


class ManifestCrypto:
    MANIFEST_SALT = b"QSP_MANIFEST_SALT_V1"
    KEY_DERIVATION_ITERATIONS = 100000
    
    VERSION_V1 = b'\x01'  
    VERSION_V2 = b'\x02'  
    VERSION_V3 = b'\x03'  
    
    ENCRYPTED_KEY_SIZE = 768 

    def __init__(self, manifest_key: bytes = None):

        if manifest_key is None:
            self.key = os.urandom(32)
        else:
            if isinstance(manifest_key, str):
                manifest_key = manifest_key.encode('utf-8')
            if len(manifest_key) != 32:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.MANIFEST_SALT,
                    iterations=self.KEY_DERIVATION_ITERATIONS,
                    backend=default_backend()
                )
                self.key = kdf.derive(manifest_key)
            else:
                self.key = manifest_key
        self.aesgcm = AESGCM(self.key)

    @classmethod
    def generate_new_key(cls):
        return cls()

    @classmethod
    def from_key(cls, key: bytes):
        if len(key) != 32:
            raise ValueError("清单密钥必须是32字节")
        return cls(key)
    
    @classmethod
    def from_password(cls, password: str):
        return cls(password)

    def encrypt_manifest(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext_with_tag = self.aesgcm.encrypt(nonce, data, associated_data=None)
        return nonce + ciphertext_with_tag

    def decrypt_manifest(self, encrypted_data: bytes) -> bytes:
        if len(encrypted_data) < 28:  
            raise ValueError("Encrypted manifest is corrupted or too short.")
        
        nonce = encrypted_data[:12]
        ciphertext_with_tag = encrypted_data[12:]

        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
            return plaintext
        except InvalidTag as e:
            raise InvalidTag("[ManifestCrypto] 清单解密失败：密钥不匹配或数据损坏！") from e

    @classmethod
    def encrypt_with_key_encapsulation(cls, data: bytes, recipient_pk: bytes) -> bytes:

        from src.crypto_lattice.encryptor import KyberKEM
        
        ciphertext, manifest_key = KyberKEM.encapsulate(recipient_pk)
        

        crypto = cls.from_key(manifest_key)
        encrypted_data = crypto.encrypt_manifest(data)
        
        result = cls.VERSION_V3 + ciphertext + encrypted_data
        
        crypto.destroy()
        return result

    @classmethod
    def decrypt_with_key_encapsulation(cls, encrypted_data: bytes, recipient_sk: bytes) -> bytes:

        from src.crypto_lattice.encryptor import KyberKEM
        
        if len(encrypted_data) < 1 + cls.ENCRYPTED_KEY_SIZE + 28:
            raise ValueError("Encrypted manifest is corrupted or too short.")
        
        version = encrypted_data[:1]
        if version != cls.VERSION_V3:
            raise ValueError(f"不支持的清单版本: {version}")
        
        encrypted_key = encrypted_data[1:1 + cls.ENCRYPTED_KEY_SIZE]
        encrypted_manifest = encrypted_data[1 + cls.ENCRYPTED_KEY_SIZE:]

        manifest_key = KyberKEM.decapsulate(encrypted_key, recipient_sk)
        
        crypto = cls.from_key(manifest_key)
        plaintext = crypto.decrypt_manifest(encrypted_manifest)
        crypto.destroy()
        
        return plaintext

    def get_key(self) -> bytes:
        return self.key

    def destroy(self):
        self.key = b""
        gc.collect()


class PasswordAuthError(Exception):
    pass

class VaultCrypto:
    MAGIC_VERIFIER = b"QSP_VAULT_MAGIC_VERIFIER"
    MANIFEST_SALT = b"QSP_MANIFEST_SALT_V1"

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
    
    def encrypt_manifest(self, data: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.MANIFEST_SALT,
            iterations=100000,
            backend=default_backend()
        )
        manifest_key = kdf.derive(self.password)
        aesgcm = AESGCM(manifest_key)
        nonce = os.urandom(12)
        ciphertext_with_tag = aesgcm.encrypt(nonce, data, associated_data=None)
        return nonce + ciphertext_with_tag
    
    def decrypt_manifest(self, encrypted_data: bytes) -> bytes:
        if len(encrypted_data) < 28:
            raise ValueError("Encrypted manifest is corrupted or too short.")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.MANIFEST_SALT,
            iterations=100000,
            backend=default_backend()
        )
        manifest_key = kdf.derive(self.password)
        aesgcm = AESGCM(manifest_key)
        
        nonce = encrypted_data[:12]
        ciphertext_with_tag = encrypted_data[12:]
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
            return plaintext
        except InvalidTag as e:
            raise InvalidTag("[VaultCrypto] 清单解密失败：密码错误或清单数据损坏！") from e
