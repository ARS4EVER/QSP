import os
import hmac
import hashlib
import gc
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# 导入配置常量
from src.config import DATA_DIR, KEYS_DIR 

# ==========================================
# 新增：自定义密码验证失败异常
# ==========================================
class PasswordAuthError(Exception):
    """当用户输入的主密码未能通过 HMAC 校验时抛出此异常"""
    pass

class VaultCrypto:
    """
    QSP 本地金库密码学套件终极版 (AES-GCM + HMAC-SHA256)
    已集成：C4物理防破、C9毫秒级防爆破、OS级原子写盘、内存级自毁机制。
    """
    MAGIC_VERIFIER = b"QSP_VAULT_MAGIC_VERIFIER"

    def __init__(self, password: str, salt_path: str = None, verifier_path: str = None, vault_dir: str = None):
        """
        初始化金库。通过用户主密码和本地随机盐派生 256 位 AES 密钥。
        
        参数说明：
        - password: 用户主密码
        - salt_path: 盐值文件路径（可选）
        - verifier_path: HMAC验证器文件路径（可选）
        - vault_dir: 金库目录路径（可选），如果提供，将在该目录下创建 .vault_salt 和 .vault_verifier
        
        兼容性处理：如果第二个参数是目录，自动将其视为 vault_dir
        """
        # 初始化状态为 None，以便在异常时安全销毁
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
            # 1. 获取或创建随机盐
            self.salt = self._get_or_create_salt()
            
            # 2. 派生 AES-256 主密钥 K_vault
            self.key = self._derive_key()
            
            # 3. 强制执行 HMAC 早期密码校验
            self._verify_or_create_authenticator()
            
            # 4. 初始化 AES-GCM
            self.aesgcm = AESGCM(self.key)
            
        except Exception as e:
            # 一旦初始化过程发生任何异常（密码错误、磁盘无空间等）
            # 立刻触发内存级自毁，防止半成品密钥驻留
            self.destroy_memory_traces()
            raise e

    def _atomic_write(self, filepath: str, data: bytes):
        """
        操作系统级原子化文件写入：
        抵御写入瞬间断电、蓝屏、磁盘满导致的文件损坏（0 字节漏洞）。
        """
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
        """
        当密码错误或发生严重异常时，最大力度清理内存中的敏感变量。
        Python 的 bytes 是不可变对象，无法直接覆写为 0。
        因此我们切断引用，并强制触发底层 C 垃圾回收器清理游离内存块。
        """
        self.password = b""
        self.key = b""
        self.salt = b""
        if self.aesgcm:
            del self.aesgcm
            self.aesgcm = None
            
        gc.collect()

    def _get_or_create_salt(self) -> bytes:
        """
        获取或创建 16 字节的密码学安全盐 (Salt)。
        如果在当前设备上是首次运行，则生成新盐并持久化。
        """
        if os.path.exists(self.salt_path):
            with open(self.salt_path, "rb") as f:
                return f.read()
        else:
            salt = os.urandom(16)
            self._atomic_write(self.salt_path, salt)
            return salt

    def _derive_key(self) -> bytes:
        """
        使用 PBKDF2-HMAC-SHA256 算法，经过 10 万次迭代，
        将用户输入的变长密码派生为 32 字节 (256 位) 的高强度主密钥。
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.password)

    def _verify_or_create_authenticator(self):
        """
        执行 HMAC-SHA256 早期校验。
        计算公式: V = HMAC-SHA256(K_vault, MAGIC_VERIFIER)
        """
        current_mac = hmac.new(self.key, self.MAGIC_VERIFIER, hashlib.sha256).digest()

        if os.path.exists(self.verifier_path):
            with open(self.verifier_path, "rb") as f:
                stored_mac = f.read()

            if not hmac.compare_digest(current_mac, stored_mac):
                raise PasswordAuthError("本地金库主密码错误，拒绝解锁！")
        else:
            self._atomic_write(self.verifier_path, current_mac)

    # ==========================================
    # 【新增功能】：任意变长数据的加解密 (用于身份私钥保护)
    # ==========================================
    
    def encrypt_data(self, data: bytes) -> bytes:
        """
        加密任意长度的字节数据（如 JSON 身份文件）。
        安全机制：
        1. 每次调用生成 12 字节随机 Nonce，防止重放与模式分析。
        2. AES-GCM 自动在密文末尾附加 16 字节的 Authentication Tag。
        
        :param data: 原始明文字节流
        :return: 打包后的密文 (格式: Nonce[12] + Ciphertext + Tag[16])
        """
        nonce = os.urandom(12)
        ciphertext_with_tag = self.aesgcm.encrypt(nonce, data, associated_data=None)
        return nonce + ciphertext_with_tag

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        解密任意长度的字节数据。
        如果用户密码错误，或者文件内容被恶意篡改，解密时将抛出 InvalidTag 异常。
        
        :param encrypted_data: 打包的密文流 (Nonce[12] + Ciphertext + Tag[16])
        :return: 解密后的原始明文字节流
        :raises InvalidTag: 密码错误或数据完整性遭到破坏时抛出
        :raises ValueError: 传入的数据格式长度不合法时抛出
        """
        if len(encrypted_data) < 28:
            raise ValueError("Encrypted data is corrupted or too short.")
            
        nonce = encrypted_data[:12]
        ciphertext_with_tag = encrypted_data[12:]
        
        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
            return plaintext
        except InvalidTag as e:
            raise InvalidTag("[VaultCrypto] 严重：密码错误或身份文件遭到篡改，拒绝解密！") from e

    # ==========================================
    # 【原有功能】：固定数据块的加解密 (向下兼容业务层切片)
    # ==========================================
    
    def encrypt_chunk(self, chunk: bytes) -> bytes:
        """
        加密 Shamir 分割后的独立数据分块。
        (底层逻辑与 encrypt_data 一致，保留此方法用于语义区分并兼容旧版 BackupManager)
        """
        return self.encrypt_data(chunk)

    def decrypt_chunk(self, encrypted_chunk: bytes) -> bytes:
        """
        解密 Shamir 分割的独立数据分块。
        (保留此方法以兼容旧版 RecoveryManager)
        """
        return self.decrypt_data(encrypted_chunk)
