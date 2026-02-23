"""
tests/test_secure_channel_phase2.py
抗量子信道安全性与边界约束测试 (公钥指纹验证版)
"""
import unittest
import sys
import os
import hashlib


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.network.secure_channel import SecureChannel, ChannelState
from src.crypto_lattice.wrapper import LatticeWrapper


class TestSecureChannelHardening(unittest.TestCase):
    def setUp(self):
        self.pk_server, self.sk_server = LatticeWrapper.generate_signing_keypair()
        self.pk_fake, self.sk_fake = LatticeWrapper.generate_signing_keypair()
        # 预先计算出服务端的公钥指纹
        self.fp_server = hashlib.sha256(self.pk_server).hexdigest()[:16]

    def test_strict_role_validation(self):
        """测试违背项修复：身份密钥缺失时必须立刻报错阻止初始化"""
        # 测试客户端缺失 peer_fp
        with self.assertRaisesRegex(ValueError, "Client requires 'peer_fp'"):
            SecureChannel(role='client', peer_fp=None)

        # 测试服务端缺失 my_sk 或 my_pk
        with self.assertRaisesRegex(ValueError, "Server requires both 'my_sk' and 'my_pk'"):
            SecureChannel(role='server', my_pk=None, my_sk=None)

    def test_handshake_crypto_pipeline(self):
        """测试正常参数下的 Kyber + Dilithium 端到端握手状态流转"""
        client_channel = SecureChannel(role='client', peer_fp=self.fp_server)
        server_channel = SecureChannel(role='server', my_pk=self.pk_server, my_sk=self.sk_server)

        # 1. 客户端发起请求
        init_payload = client_channel.initiate_handshake()
        self.assertEqual(client_channel.state, ChannelState.HANDSHAKING)

        # 2. 服务端处理并返回带签名的密文
        resp_payload = server_channel.handle_handshake_request(init_payload)
        self.assertEqual(server_channel.state, ChannelState.ESTABLISHED)

        # 3. 客户端验证身份并建立加密连接
        client_channel.handle_handshake_response(resp_payload)
        self.assertEqual(client_channel.state, ChannelState.ESTABLISHED)

        # 4. 验证最终协商出的 AES 密钥完全一致
        self.assertIsNotNone(client_channel.session_key)
        self.assertEqual(client_channel.session_key, server_channel.session_key)

    def test_mitm_fingerprint_mismatch(self):
        """测试安全拦截：恶意节点试图用自己的密钥对假冒服务端"""
        client_channel = SecureChannel(role='client', peer_fp=self.fp_server)
        # 攻击者节点
        hacker_channel = SecureChannel(role='server', my_pk=self.pk_fake, my_sk=self.sk_fake)

        init_payload = client_channel.initiate_handshake()
        hacker_payload = hacker_channel.handle_handshake_request(init_payload)

        # 客户端在第一步比对指纹时，就应该果断阻断攻击！
        with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
            client_channel.handle_handshake_response(hacker_payload)


if __name__ == '__main__':
    unittest.main()
