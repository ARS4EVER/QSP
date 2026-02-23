import unittest
import time
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.network.p2p_manager import P2PNode, InviteCodeManager
from src.crypto_lattice.wrapper import LatticeWrapper
from src.network.secure_channel import ChannelState


class TestP2PMultiplexing(unittest.TestCase):
    def setUp(self):
        self.pk_a, self.sk_a = LatticeWrapper.generate_signing_keypair()
        self.pk_b, self.sk_b = LatticeWrapper.generate_signing_keypair()

        self.node_a = P2PNode(port=0, dil_pk=self.pk_a, static_sk=self.sk_a)
        self.node_b = P2PNode(port=0, dil_pk=self.pk_b, static_sk=self.sk_b)
        
        self.node_a.start()
        self.node_b.start()

    def tearDown(self):
        self.node_a.stop()
        self.node_b.stop()

    def test_secure_links_multiplexing_dict(self):
        port_a = self.node_a.sock.getsockname()[1]
        port_b = self.node_b.sock.getsockname()[1]
        
        invite_b = self.node_b.generate_invite_code()
        self.node_a.connect_via_invite(invite_b, session_id=123)
        
        time.sleep(2.0)
        
        addr_a_actual = None
        for addr in self.node_b.secure_links.keys():
            if addr[1] == port_a:
                addr_a_actual = addr
                break
                
        addr_b_actual = None
        for addr in self.node_a.secure_links.keys():
            if addr[1] == port_b:
                addr_b_actual = addr
                break

        self.assertIsNotNone(addr_a_actual, "Node B 没有接收到来自真实物理网卡的连接")
        self.assertIsNotNone(addr_b_actual, "Node A 没有建立往真实物理网卡的连接")
        
        link_a = self.node_a.secure_links[addr_b_actual]
        link_b = self.node_b.secure_links[addr_a_actual]
        self.assertEqual(link_a.sec_channel.state, ChannelState.ESTABLISHED)
        self.assertEqual(link_b.sec_channel.state, ChannelState.ESTABLISHED)


if __name__ == '__main__':
    unittest.main()
