import time
import json
import unittest
from unittest.mock import patch

from src.core.challenge_auth import ChallengeManager, build_auth_payload

class TestC8ClockSyncAndReplay(unittest.TestCase):
    """
    QSP 系统 C8 标准专项测试套件：
    测试无时钟同步依赖、单调时间过期机制、阅后即焚（防重放）以及签名负载的语义绑定。
    """

    def setUp(self):
        """测试前置准备"""
        # 设置一个较短的 TTL 用于测试 (例如 5 秒)
        self.ttl = 5
        self.cm = ChallengeManager(ttl_seconds=self.ttl)
        self.node_a = "node_A_id_123"
        self.node_b = "node_B_id_456"

    # ==========================================
    # 测试环节 1: 基础的挑战-应答握手
    # ==========================================
    def test_01_generate_and_verify_success(self):
        """测试正常的挑战码生成与验证流程"""
        nonce = self.cm.generate_challenge(self.node_a)
        
        # 验证 Nonce 格式为 32 字节 Hex (即 64 个字符)
        self.assertEqual(len(nonce), 64)
        self.assertTrue(isinstance(nonce, str))
        
        # 正常验证应当通过
        is_valid = self.cm.verify_and_burn(self.node_a, nonce)
        self.assertTrue(is_valid, "合法的挑战码应当验证通过")

    def test_02_verify_wrong_node(self):
        """测试 A 节点申请的挑战码，B 节点不能使用 (防身份混淆)"""
        nonce = self.cm.generate_challenge(self.node_a)
        
        # B 试图用 A 的 Nonce 来验证
        is_valid = self.cm.verify_and_burn(self.node_b, nonce)
        self.assertFalse(is_valid, "节点 ID 不匹配时应当拒绝验证")

    # ==========================================
    # 测试环节 2: 阅后即焚机制 (防重放攻击绝杀)
    # ==========================================
    def test_03_burn_after_reading_prevents_replay(self):
        """测试验证通过后，Nonce 被瞬间销毁，重放窗口压缩为 0"""
        nonce = self.cm.generate_challenge(self.node_a)
        
        # 第一次请求：正常的 PULL_REQ
        first_attempt = self.cm.verify_and_burn(self.node_a, nonce)
        self.assertTrue(first_attempt, "首次合法验证应当通过")
        
        # 第二次请求：黑客截获了上一个请求，原封不动地发起了重放攻击 (Replay Attack)
        second_attempt = self.cm.verify_and_burn(self.node_a, nonce)
        
        # 由于采用了阅后即焚，缓存已被清空，第二次应当直接失败
        self.assertFalse(second_attempt, "严重的重放攻击漏洞：同一个 Nonce 被成功验证了两次！")

    # ==========================================
    # 测试环节 3: 摆脱时钟同步 (依赖单调时钟而非系统时间)
    # ==========================================
    @patch('time.monotonic')
    def test_04_monotonic_time_expiration(self, mock_monotonic):
        """测试挑战码的过期机制完全依赖单调时钟，符合 C8 无时钟同步标准"""
        
        # 假设当前系统单调开机时间为 1000.0 秒
        mock_monotonic.return_value = 1000.0
        
        # 生成挑战码，TTL 为 5 秒，预期在 1005.0 秒过期
        nonce = self.cm.generate_challenge(self.node_a)
        
        # 1. 模拟网络传输耗时 2 秒 (1002.0)，此时尚未过期
        mock_monotonic.return_value = 1002.0
        # 注意：这里我们不能调用 verify_and_burn，因为那会把它销毁。
        # 我们仅模拟单调时间的推进，证明超时判定生效。
        
        # 2. 模拟网络极度拥堵或恶意延迟，时间推进到 1006.0 秒 (已超过 5 秒)
        mock_monotonic.return_value = 1006.0
        
        is_valid = self.cm.verify_and_burn(self.node_a, nonce)
        self.assertFalse(is_valid, "过期的挑战码应当被拒绝，单调时钟防御失效！")

    # ==========================================
    # 测试环节 4: 签名负载的语义绑定 (防止伪造请求)
    # ==========================================
    def test_05_payload_semantic_binding(self):
        """测试最终用于抗量子签名的字节流是否严格绑定了所有参数，防止篡改"""
        file_hash_1 = "hash_A"
        file_hash_2 = "hash_B"
        nonce = "random_nonce_123"
        threshold = 3
        
        # 构建负载 1
        payload_1 = build_auth_payload(file_hash_1, threshold, nonce)
        # 构建负载 2 (仅仅改变了企图恢复的文件哈希)
        payload_2 = build_auth_payload(file_hash_2, threshold, nonce)
        
        # 确保只要改变了一个业务参数，最终要签名的原文就彻底改变
        self.assertNotEqual(payload_1, payload_2, "负载未严格绑定，存在被篡改请求的风险！")
        
        # 验证序列化的一致性 (JSON 的 keys 是否排序，分隔符是否一致)
        # 如果不一致，C/S 两端在验签时会因为 JSON 字符串的空格差异导致失败
        decoded_1 = json.loads(payload_1.decode('utf-8'))
        self.assertEqual(decoded_1["nonce"], nonce)
        self.assertEqual(decoded_1["file_hash"], file_hash_1)
        
        # 确保使用了紧凑格式 (没有任何多余空格)
        self.assertNotIn(b" ", payload_1, "签名的 JSON 字节流中包含不可预期的空格，会导致跨语言验签失败！")

if __name__ == "__main__":
    unittest.main(verbosity=2)
