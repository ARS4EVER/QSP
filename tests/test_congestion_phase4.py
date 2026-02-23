import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.network.congestion import HybridCongestionControl

class TestHybridCongestionControl(unittest.TestCase):

    def setUp(self):
        self.cc = HybridCongestionControl(initial_cwnd=10.0, max_cwnd=1000.0)

    def test_slow_start(self):
        """测试慢启动阶段的指数级（每个ACK加1）增长"""
        initial_cwnd = self.cc.cwnd
        for _ in range(5):
            self.cc.on_ack(rtt=0.010)
            
        self.assertEqual(self.cc.get_cwnd_packets(), int(initial_cwnd + 5))

    def test_dynamic_additive_increase_low_delay(self):
        """测试低延迟环境下的动态高增益增长"""
        self.cc.cwnd = 100.0
        self.cc.ssthresh = 50.0
        
        self.cc.on_ack(rtt=0.010)
        
        cwnd_before = self.cc.cwnd
        self.cc.on_ack(rtt=0.010)
        
        growth = self.cc.cwnd - cwnd_before
        self.assertTrue(0.09 < growth < 0.11, f"实际增长: {growth}")

    def test_dynamic_additive_increase_high_delay(self):
        """测试高排队延迟环境下的平滑退让"""
        self.cc.cwnd = 100.0
        self.cc.ssthresh = 50.0
        
        self.cc.on_ack(rtt=0.010)
        
        cwnd_before = self.cc.cwnd
        self.cc.on_ack(rtt=0.020)
        
        growth = self.cc.cwnd - cwnd_before
        self.assertTrue(0.009 < growth < 0.011, f"实际增长: {growth}")

    def test_multiplicative_decrease_random_loss(self):
        """测试高带宽常见痛点：极低随机丢包不应导致窗口减半"""
        self.cc.cwnd = 200.0
        
        for _ in range(99):
            self.cc.on_ack(rtt=0.015)
            
        cwnd_before_loss = self.cc.cwnd
        
        self.cc.on_loss()
        
        expected_cwnd = int(cwnd_before_loss * 0.95)
        self.assertEqual(self.cc.get_cwnd_packets(), expected_cwnd)

    def test_multiplicative_decrease_congestion_loss(self):
        """测试真实拥塞场景：高频丢包时应当激进收缩 (减半)"""
        self.cc.cwnd = 200.0
        
        for _ in range(50):
            self.cc.on_ack(rtt=0.100)
        for _ in range(49):
            self.cc.on_loss()
            
        cwnd_before_final_loss = self.cc.cwnd
        
        self.cc.on_loss()
        
        expected_cwnd = max(10, int(cwnd_before_final_loss * 0.5))
        self.assertEqual(self.cc.get_cwnd_packets(), expected_cwnd)

if __name__ == "__main__":
    unittest.main()
