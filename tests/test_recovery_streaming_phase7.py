"""
tests/test_recovery_streaming_phase7.py
测试基于 .part/.meta 的网络乱序分块接收与断点续传，以及大文件的终极流式重构闭环。
"""
import unittest
import os
import tempfile
import shutil
import json
import hashlib
import sys
from unittest.mock import MagicMock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.app.recovery_manager import RecoveryManager
from src.app.app_protocol import AppMessage, AppCmd
from src.secret_sharing.splitter import SecretSplitter
from src.app.vault_crypto import VaultCrypto

class TestRecoveryStreamingPart(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.vault_dir = os.path.join(self.test_dir, "vault")
        os.makedirs(self.vault_dir)

        self.mock_node = MagicMock()
        self.mock_node.secure_link = MagicMock()
        
        # 【核心修复 1】显式传入本地加密密码和金库路径
        self.vault_pwd = "test_password_123"
        self.crypto = VaultCrypto(self.vault_pwd, self.vault_dir)
        self.rm = RecoveryManager(self.mock_node, vault_password=self.vault_pwd, vault_dir=self.vault_dir)

        self.original_data = os.urandom(2000) 
        self.file_hash = hashlib.sha256(self.original_data).hexdigest()

        self.manifest_path = os.path.join(self.test_dir, "manifest.json")
        with open(self.manifest_path, "w") as f:
            json.dump({
                "filename": "test_asset.bin",
                "original_hash": self.file_hash,
                "t": 2, "n": 3
            }, f)

        chunks = [self.original_data[i:i+512] for i in range(0, len(self.original_data), 512)]
        self.share_1_chunks = []
        self.share_2_chunks = []

        for chunk in chunks:
            shares = SecretSplitter.split_secret(chunk, 2, 3)
            self.share_1_chunks.append(shares[0][1])
            self.share_2_chunks.append(shares[1][1])

        share1_path = os.path.join(self.vault_dir, f"{self.file_hash}_share_1.dat")
        with open(share1_path, "wb") as f:
            for c in self.share_1_chunks:
                # 【核心修复 2】提前埋入硬盘的模拟数据，必须经过透明加密！
                f.write(self.crypto.encrypt_chunk(c))

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_part_reconstruction_out_of_order(self):
        success_called = []
        self.rm.on_recovery_success = lambda fh, path: success_called.append(path)

        self.rm.execute_recovery(self.manifest_path)
        total_chunks = len(self.share_2_chunks)
        out_of_order_indices = [2, 0, 3, 1]

        for i, chunk_idx in enumerate(out_of_order_indices):
            msg = AppMessage(
                cmd=AppCmd.PULL_RESP, file_hash=self.file_hash, share_index=2,
                share_data=self.share_2_chunks[chunk_idx], chunk_index=chunk_idx, total_chunks=total_chunks
            )
            self.rm.handle_pull_response(("127.0.0.1", 9999), msg)

            if i < len(out_of_order_indices) - 1:
                part_exists = os.path.exists(os.path.join(self.vault_dir, f"{self.file_hash}_share_2.part"))
                self.assertTrue(part_exists, "乱序包未能正确落盘为 .part 文件！")

        self.assertFalse(os.path.exists(os.path.join(self.vault_dir, f"{self.file_hash}_share_2.part")))
        self.assertTrue(os.path.exists(os.path.join(self.vault_dir, f"{self.file_hash}_share_2.dat")))
        self.assertEqual(len(success_called), 1)

        with open(success_called[0], "rb") as f:
            self.assertEqual(f.read(), self.original_data)

if __name__ == '__main__':
    unittest.main()
