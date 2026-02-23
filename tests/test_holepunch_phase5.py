import unittest
import time
import sys
import os
import threading

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.network.p2p_manager import P2PNode, PunchState, InviteCodeManager
from src.crypto_lattice.wrapper import LatticeWrapper


class TestHolePunchStateMachine(unittest.TestCase):
    def setUp(self):
        self.pk_a, self.sk_a = LatticeWrapper.generate_signing_keypair()
        
        self.node_a = P2PNode(port=0, dil_pk=self.pk_a, static_sk=self.sk_a)
        self.node_b = P2PNode(port=0, dil_pk=self.pk_a, static_sk=self.sk_a)
        
        self.node_a.port = self.node_a.sock.getsockname()[1]
        self.node_b.port = self.node_b.sock.getsockname()[1]
        
        self.node_a.start()
        self.node_b.start()

    def tearDown(self):
        self.node_a.stop()
        self.node_b.stop()

    def test_state_machine_direct_transitions(self):
        self.assertEqual(self.node_a.punch_state, PunchState.IDLE)
        self.node_a._mark_connected(("192.168.1.99", 12345), 100, role='server')
        self.assertEqual(self.node_a.punch_state, PunchState.CONNECTED)
        self.assertEqual(self.node_a.peer_addr, ("192.168.1.99", 12345))

    def test_concurrent_holepunch_success(self):
        self.node_a.target_peer_pk = self.node_b.dil_pk
        self.node_b.target_peer_pk = self.node_a.dil_pk
        
        invite_code_a = self.node_a.generate_invite_code()
        invite_code_b = self.node_b.generate_invite_code()
        
        session_id = 999
        
        # 1. 确保起步前状态干净
        self.assertEqual(self.node_a.punch_state, PunchState.IDLE)
        self.assertEqual(self.node_b.punch_state, PunchState.IDLE)
        
        # 2. 先启动 node_a，验证它进入 PUNCHING 状态
        self.node_a.connect_via_invite(invite_code_b, session_id)
        self.assertEqual(self.node_a.punch_state, PunchState.PUNCHING, "node_a 状态机未能正确进入 UDP 盲打阶段")
        
        # 3. 再启动 node_b，验证它也进入 PUNCHING 状态
        self.node_b.connect_via_invite(invite_code_a, session_id)
        self.assertEqual(self.node_b.punch_state, PunchState.PUNCHING, "node_b 状态机未能正确进入 UDP 盲打阶段")
        
        # 4. 挂起主线程，让真实的 UDP 包通过网卡飞行并完成抗量子握手
        time.sleep(1.5)
        
        # 5. 断言终态，验证物理穿透闭环
        self.assertEqual(self.node_a.punch_state, PunchState.CONNECTED, "node_a 未能完成穿透")
        self.assertEqual(self.node_b.punch_state, PunchState.CONNECTED, "node_b 未能完成穿透")
        
        connected_to_b = False
        for addr in self.node_a.secure_links.keys():
            if addr[1] == self.node_b.port:
                connected_to_b = True
                break
        self.assertTrue(connected_to_b, "Node A 未能在真实的物理网卡上完成穿透响应")


if __name__ == "__main__":
    unittest.main()
