"""
tests/test_keepalive_phase8.py
test_keepalive_phase8.py
测试网络层的 KEEPALIVE 自动心跳引擎，验证防 NAT 老化机制。
"""
import unittest
import time
import sys
import os
from unittest.mock import MagicMock


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.network.secure_link import SecureLink
from src.network.secure_channel import ChannelState
from src.network.protocol import QSPProtocol, PacketType


class TestHeartbeatKeepAlive(unittest.TestCase):

    def test_automatic_heartbeat_emission(self):
        """测试：在信道空闲时，守护线程必须自动发出 KEEPALIVE 探测包"""
        mock_send = MagicMock()
        
        # 实例化安全链路
        link = SecureLink(
            send_raw_fn=mock_send, 
            peer_addr=("192.168.1.100", 8888), 
            session_id=1, 
            role='client',
            peer_fp="dummy_fp"
        )
        
        # 强制将状态置为 ESTABLISHED 以激活心跳机制
        link.sec_channel.state = ChannelState.ESTABLISHED
        
        # 为了加快测试速度，将原本 15 秒的保活阈值压缩为 0.5 秒
        link.heartbeat_interval = 0.5
        
        # 挂机等待 2.1 秒（应该能触发至少 2 次心跳包喷射）
        time.sleep(2.1)
        
        # 测试结束，安全释放心跳线程
        link.stop()
        
        # 统计抓到的 KEEPALIVE 数据包数量
        keepalive_count = 0
        for call in mock_send.call_args_list:
            raw_bytes = call[0][0]
            parsed = QSPProtocol.unpack(raw_bytes)
            if parsed['type'] == PacketType.KEEPALIVE:
                keepalive_count += 1
                
        self.assertGreaterEqual(keepalive_count, 2, "心跳保活线程未能如期喷射足够数量的维持包！")

    def test_heartbeat_reception_updates_timestamp(self):
        """测试：接收到 KEEPALIVE 包时，必须静默刷新接收时间，不能干扰上层业务流"""
        mock_send = MagicMock()
        link = SecureLink(
            send_raw_fn=mock_send, 
            peer_addr=("192.168.1.100", 8888), 
            session_id=1, 
            role='server',
            local_pk=b"dummy_pk",
            local_sk=b"dummy_sk"
        )
        
        # 将接收时间篡改为远古时期
        link.last_recv_time = 0.0
        
        # 伪造一个来自远端的心跳包
        keepalive_pkt = QSPProtocol.pack(PacketType.KEEPALIVE, seq=0, payload=b"PING")
        parsed_pkt = QSPProtocol.unpack(keepalive_pkt)
        
        # 送入处理核心
        link.handle_network_packet(parsed_pkt)
        
        # 验证：接收时间戳必须被刷新为最新时间
        self.assertGreater(link.last_recv_time, 0.0, "接收到保活包后未正确刷新存活时间！")
        
        link.stop()


if __name__ == "__main__":
    unittest.main()
