import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import hashlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.network.secure_link import SecureLink
from src.network.protocol import QSPProtocol, PacketType
from src.network.secure_channel import ChannelState
from src.crypto_lattice.wrapper import LatticeWrapper


class TestSecureLinkPipeline(unittest.TestCase):
    def setUp(self):
        self.session_id = 8888
        self.peer_addr_a = ("192.168.1.10", 10000)
        self.peer_addr_b = ("192.168.1.20", 20000)

        def send_from_a(data, addr):
            self.link_b.handle_network_packet(QSPProtocol.unpack(data))

        def send_from_b(data, addr):
            self.link_a.handle_network_packet(QSPProtocol.unpack(data))

        # 生成测试用的密钥对
        self.pk_a, self.sk_a = LatticeWrapper.generate_signing_keypair()
        self.pk_b, self.sk_b = LatticeWrapper.generate_signing_keypair()
        # 计算指纹
        self.fp_a = hashlib.sha256(self.pk_a).hexdigest()[:16]
        self.fp_b = hashlib.sha256(self.pk_b).hexdigest()[:16]

        with patch('src.network.secure_link.SecureChannel') as MockSC:
            mock_channel_a = MagicMock()
            mock_channel_b = MagicMock()
            mock_channel_a.state = ChannelState.NONE
            mock_channel_b.state = ChannelState.NONE
            
            mock_channel_a.role = 'client'
            mock_channel_b.role = 'server'
            
            MockSC.side_effect = [mock_channel_a, mock_channel_b]

            self.link_a = SecureLink(
                send_from_a, self.peer_addr_b, self.session_id, 
                role='client', peer_fp=self.fp_b, local_pk=self.pk_a, local_sk=self.sk_a
            )
            self.link_b = SecureLink(
                send_from_b, self.peer_addr_a, self.session_id, 
                role='server', peer_fp=self.fp_a, local_pk=self.pk_b, local_sk=self.sk_b
            )

            self.link_a.sec_channel = mock_channel_a
            self.link_b.sec_channel = mock_channel_b

            mock_channel_a.initiate_handshake.return_value = b"INIT_DATA"
            
            def b_handle_req(payload):
                mock_channel_b.state = ChannelState.ESTABLISHED
                return b"RESP_DATA"
            mock_channel_b.handle_handshake_request.side_effect = b_handle_req
            
            def a_handle_resp(payload=None):
                mock_channel_a.state = ChannelState.ESTABLISHED
            mock_channel_a.handle_handshake_response.side_effect = a_handle_resp
            
            mock_channel_a.encrypt_payload = lambda x: b"ENC_" + x
            mock_channel_b.decrypt_payload = lambda x: x[4:]

    def test_handshake_injection_and_data_flow(self):
        handshake_events = []
        self.link_a.on_handshake_done = lambda: handshake_events.append("A_DONE")
        self.link_b.on_handshake_done = lambda: handshake_events.append("B_DONE")

        self.link_a.initiate_security_handshake()
        
        self.assertEqual(self.link_a.sec_channel.state, ChannelState.ESTABLISHED)
        self.assertIn("A_DONE", handshake_events)
        self.assertIn("B_DONE", handshake_events)

        received_data = []
        self.link_b.on_data_received = lambda data: received_data.append(data)

        self.link_a.send_reliable(b"SHAMIR_SHARE_1")
        
        self.assertEqual(len(received_data), 1)
        self.assertEqual(received_data[0], b"SHAMIR_SHARE_1")


if __name__ == "__main__":
    unittest.main()
