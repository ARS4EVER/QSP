import unittest
import time
import threading
from unittest.mock import patch

from src.core.challenge_auth import ChallengeManager, build_auth_payload


class TestChallengeAuth(unittest.TestCase):
    """
    C8标准专项测试：挑战-应答管理器与单调时钟安全
    """

    def test_01_challenge_generation(self):
        """测试挑战随机数的生成是否安全"""
        manager = ChallengeManager()
        
        node1 = "node_001"
        nonce1 = manager.generate_challenge(node1)
        
        self.assertIsNotNone(nonce1)
        self.assertEqual(len(nonce1), 64)

    def test_02_valid_verification(self):
        """测试有效Nonce的验证流程"""
        manager = ChallengeManager()
        
        node1 = "node_001"
        nonce1 = manager.generate_challenge(node1)
        
        result = manager.verify_and_burn(node1, nonce1)
        self.assertTrue(result)

    def test_03_burn_after_reading(self):
        """测试阅后即焚机制防止重放攻击"""
        manager = ChallengeManager()
        
        node1 = "node_001"
        nonce1 = manager.generate_challenge(node1)
        
        result1 = manager.verify_and_burn(node1, nonce1)
        self.assertTrue(result1)
        
        result2 = manager.verify_and_burn(node1, nonce1)
        self.assertFalse(result2)

    def test_04_wrong_nonce_rejected(self):
        """测试错误的Nonce被正确拒绝"""
        manager = ChallengeManager()
        
        node1 = "node_001"
        nonce1 = manager.generate_challenge(node1)
        
        wrong_nonce = "0000000000000000000000000000000000000000000000000000000000000000"
        result = manager.verify_and_burn(node1, wrong_nonce)
        
        self.assertFalse(result)

    def test_05_nonce_expired(self):
        """测试TTL超时机制"""
        manager = ChallengeManager(ttl_seconds=1)
        
        node1 = "node_001"
        nonce1 = manager.generate_challenge(node1)
        
        time.sleep(1.5)
        
        result = manager.verify_and_burn(node1, nonce1)
        self.assertFalse(result)

    def test_06_thread_safety(self):
        """测试多线程并发下的安全性"""
        manager = ChallengeManager()
        results = []
        lock = threading.Lock()
        
        def test_thread(node_id):
            nonce = manager.generate_challenge(node_id)
            result = manager.verify_and_burn(node_id, nonce)
            with lock:
                results.append(result)
        
        threads = []
        for i in range(10):
            t = threading.Thread(target=test_thread, args=(f"node_{i:03d}",))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        self.assertEqual(len(results), 10)
        self.assertTrue(all(results))

    def test_07_auth_payload_building(self):
        """测试认证负载的构建与确定性"""
        file_hash = "abcdef1234567890"
        threshold = 3
        nonce = "deadbeefcafebabe"
        
        payload1 = build_auth_payload(file_hash, threshold, nonce)
        payload2 = build_auth_payload(file_hash, threshold, nonce)
        
        self.assertEqual(payload1, payload2)
        self.assertIsInstance(payload1, bytes)
        
        payload_str = payload1.decode('utf-8')
        self.assertIn('"file_hash":"abcdef1234567890"', payload_str)
        self.assertIn('"threshold":3', payload_str)
        self.assertIn('"nonce":"deadbeefcafebabe"', payload_str)

    @patch("time.monotonic")
    def test_08_monotonic_usage(self, mock_monotonic):
        """测试使用的是单调时钟而非系统时钟"""
        mock_monotonic.return_value = 1000.0
        
        manager = ChallengeManager()
        node1 = "node_001"
        
        manager.generate_challenge(node1)
        
        mock_monotonic.assert_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
