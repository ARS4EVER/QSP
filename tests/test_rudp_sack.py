import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.network.rudp import RUDPConnection

class TestRUDPSACKEngine(unittest.TestCase):

    def setUp(self):
        self.conn = RUDPConnection(session_id=12345)

    def test_sequential_receive(self):
        """测试正常顺序到达的数据交付"""
        data1, ack1, sack1 = self.conn.receive_data(1, b"Packet1")
        self.assertEqual(len(data1), 1)
        self.assertEqual(ack1, 1)
        self.assertEqual(len(sack1), 0)
        
        data2, ack2, sack2 = self.conn.receive_data(2, b"Packet2")
        self.assertEqual(data2[0], b"Packet2")
        self.assertEqual(ack2, 2)

    def test_out_of_order_receive_and_sack_generation(self):
        """测试乱序到达时：生成 SACK 块及后续恢复连贯交付"""
        self.conn.receive_data(1, b"P1")
        
        d3, ack3, sack3 = self.conn.receive_data(3, b"P3")
        self.assertEqual(len(d3), 0)
        self.assertEqual(ack3, 1)
        self.assertEqual(sack3, [(3, 3)])
        
        d4, ack4, sack4 = self.conn.receive_data(4, b"P4")
        self.assertEqual(sack4, [(3, 4)])
        
        d2, ack2, sack2 = self.conn.receive_data(2, b"P2")
        self.assertEqual(len(d2), 3)
        self.assertEqual(d2[0], b"P2")
        self.assertEqual(d2[2], b"P4")
        self.assertEqual(ack2, 4)
        self.assertEqual(len(sack2), 0)

    def test_fast_retransmit_trigger(self):
        """测试发送端逻辑：接收 3 次重复的 SACK 跳跃后触发快速重传"""
        for i in range(1, 6):
            self.conn.track_sent_packet(seq=i, payload=f"P{i}".encode())
            
        self.conn.handle_sack(ack=1, sack_blocks=[])
        self.assertNotIn(1, self.conn.unacked_packets)
        
        retransmits, _ = self.conn.handle_sack(ack=1, sack_blocks=[(3, 3)])
        self.assertEqual(len(retransmits), 0)
        self.assertEqual(self.conn.unacked_packets[2]['sack_count'], 1)
        
        retransmits, _ = self.conn.handle_sack(ack=1, sack_blocks=[(3, 4)])
        self.assertEqual(len(retransmits), 0)
        self.assertEqual(self.conn.unacked_packets[2]['sack_count'], 2)
        
        retransmits, _ = self.conn.handle_sack(ack=1, sack_blocks=[(3, 5)])
        
        self.assertEqual(len(retransmits), 1)
        self.assertEqual(retransmits[0][0], 2)
        self.assertEqual(retransmits[0][1], b"P2")
        
        self.assertNotIn(3, self.conn.unacked_packets)
        self.assertNotIn(5, self.conn.unacked_packets)

if __name__ == '__main__':
    unittest.main()
