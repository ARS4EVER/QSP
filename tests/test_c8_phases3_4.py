import unittest
import os
import tempfile
import base64
from unittest.mock import MagicMock, Mock, patch

from src.core.recovery_participant import RecoveryParticipant
from src.core.challenge_auth import ChallengeManager
from src.app.app_protocol import AppMessageV2, AppCmdV2, build_challenge_req, build_challenge_resp


class TestRecoveryParticipantPhase3(unittest.TestCase):
    """
    C8标准第三阶段测试：接收端（份额持有方）状态机改造
    """

    def setUp(self):
        self.mock_p2p_node = MagicMock()
        self.mock_p2p_node.node_id = "server_node"
        self.mock_vault_crypto = MagicMock()
        
        self.participant = RecoveryParticipant(
            p2p_node=self.mock_p2p_node,
            vault_crypto=self.mock_vault_crypto
        )

    def test_challenge_manager_initialized(self):
        """测试ChallengeManager正确初始化"""
        self.assertIsInstance(self.participant.challenge_manager, ChallengeManager)

    def test_handle_challenge_req_generates_nonce(self):
        """测试处理挑战请求并生成Nonce"""
        msg = build_challenge_req("client_node")
        
        self.participant._handle_challenge_req("client_node", msg)
        
        self.mock_p2p_node.send_message.assert_called_once()
        call_args = self.mock_p2p_node.send_message.call_args
        response_msg = call_args[0][1]
        
        self.assertEqual(response_msg.cmd, AppCmdV2.CHALLENGE_RESP)
        self.assertIn("nonce", response_msg.payload)
        self.assertEqual(len(response_msg.payload["nonce"]), 64)

    def test_verify_and_burn_blocks_replay(self):
        """测试阅后即焚机制阻止重放攻击"""
        msg1 = build_challenge_req("client_node")
        self.participant._handle_challenge_req("client_node", msg1)
        
        call_args = self.mock_p2p_node.send_message.call_args
        response_msg = call_args[0][1]
        nonce = response_msg.payload["nonce"]
        
        result1 = self.participant.challenge_manager.verify_and_burn("client_node", nonce)
        self.assertTrue(result1)
        
        result2 = self.participant.challenge_manager.verify_and_burn("client_node", nonce)
        self.assertFalse(result2)

    def test_handle_pull_req_with_invalid_nonce(self):
        """测试使用无效Nonce的拉取请求被拒绝"""
        fake_msg = MagicMock()
        fake_msg.payload = {
            "file_hash": "test_hash",
            "threshold": 3,
            "nonce": "invalid_nonce",
            "signature": "fake_sig",
            "public_key": "fake_pk"
        }
        
        self.participant._handle_pull_req("client_node", fake_msg)
        
        self.mock_p2p_node.send_message.assert_called()
        call_args = self.mock_p2p_node.send_message.call_args
        reject_msg = call_args[0][1]
        
        self.assertEqual(reject_msg.payload.get("reason"), "挑战码验证失败、已过期或已被消耗，拒绝请求。")


class TestChallengeResponsePhase4(unittest.TestCase):
    """
    C8标准第四阶段测试：请求端（恢复发起方）挑战应答交互流
    """

    def test_build_challenge_req_structure(self):
        """测试挑战请求报文结构"""
        req = build_challenge_req("requester_node")
        
        self.assertEqual(req.cmd, AppCmdV2.CHALLENGE_REQ)
        self.assertEqual(req.sender_id, "requester_node")
        self.assertEqual(req.payload["requester_id"], "requester_node")

    def test_build_challenge_resp_structure(self):
        """测试挑战响应报文结构"""
        nonce = "a" * 64
        resp = build_challenge_resp("server_node", nonce)
        
        self.assertEqual(resp.cmd, AppCmdV2.CHALLENGE_RESP)
        self.assertEqual(resp.sender_id, "server_node")
        self.assertEqual(resp.payload["nonce"], nonce)

    def test_roundtrip_challenge_flow(self):
        """测试完整的挑战-应答流程"""
        requester_id = "client_node"
        server_id = "server_node"
        
        challenge_req = build_challenge_req(requester_id)
        encoded_req = challenge_req.encode()
        
        decoded_req = AppMessageV2.decode(encoded_req)
        self.assertEqual(decoded_req.cmd, AppCmdV2.CHALLENGE_REQ)
        self.assertEqual(decoded_req.payload["requester_id"], requester_id)
        
        manager = ChallengeManager()
        nonce = manager.generate_challenge(requester_id)
        
        challenge_resp = build_challenge_resp(server_id, nonce)
        encoded_resp = challenge_resp.encode()
        
        decoded_resp = AppMessageV2.decode(encoded_resp)
        self.assertEqual(decoded_resp.cmd, AppCmdV2.CHALLENGE_RESP)
        self.assertEqual(decoded_resp.payload["nonce"], nonce)
        
        verification = manager.verify_and_burn(requester_id, nonce)
        self.assertTrue(verification)


if __name__ == "__main__":
    unittest.main(verbosity=2)
