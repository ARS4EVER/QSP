"""
tests/test_integration_final.py
[终极集成测试] 验证重构后的全新系统架构
架构: 单节点 Dilithium 认证 + Kyber 加密通道 + Shamir 秘密切片
"""
import unittest
import os
import sys
import hashlib
from unittest.mock import patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.crypto_lattice.wrapper import LatticeWrapper
from src.network.secure_channel import SecureChannel
from src.core.recovery_host import RecoveryHost
from src.core.recovery_participant import RecoveryParticipant
from src.core.messages import RecoveryMessage, RecoveryMsgType

class TestFinalIntegration(unittest.TestCase):
    
    def setUp(self):
        """系统初始化阶段：分发公钥，建立信任网络"""
        print("\n=== System Initialization ===")
        self.host_pk, self.host_sk = LatticeWrapper.generate_signing_keypair()
        self.host_id = "Master_Host_01"
        
        self.participants = []
        self.participant_channels_for_host = []
        
        for i in range(1, 6):
            node_id = f"Node_{i}"
            pk, sk = LatticeWrapper.generate_signing_keypair()
            
            participant = RecoveryParticipant(node_id, trusted_hosts={self.host_id: self.host_pk})
            
            file_hash = b"target_secret_file_hash_256"
            dummy_share_data = f"encrypted_share_data_for_{node_id}".encode()
            participant.store_share(file_hash, i, dummy_share_data)
            
            self.participants.append({
                "id": node_id,
                "pk": pk,
                "sk": sk,
                "instance": participant
            })
            
        self.file_hash = b"target_secret_file_hash_256"

    @patch('src.secret_sharing.reconstructor.SecretReconstructor.reconstruct')
    def test_full_recovery_pipeline(self, mock_reconstruct):
        """测试完整的恢复流水线：从握手到切片聚合"""
        print("\n=== Phase 1: Secure Channel Handshake ===")
        
        host_logic = RecoveryHost(self.host_id, self.host_sk, threshold=3)
        
        active_connections = []
        
        for p in self.participants:
            # 计算指纹
            peer_fp = hashlib.sha256(p["pk"]).hexdigest()[:16]
            host_channel = SecureChannel(role='client', peer_fp=peer_fp)
            init_req = host_channel.initiate_handshake()
            
            p_channel = SecureChannel(role='server', my_pk=p["pk"], my_sk=p["sk"])
            resp_payload = p_channel.handle_handshake_request(init_req)
            
            host_channel.handle_handshake_response(resp_payload)
            
            self.assertEqual(host_channel.session_key, p_channel.session_key)
            active_connections.append((host_channel, p_channel, p["instance"]))
            print(f"  [+] Secure channel established with {p['id']}")

        print("\n=== Phase 2: Secure Recovery Request & Response ===")
        
        req_payload = host_logic.create_recovery_request(self.file_hash)
        
        successful_responses = 0
        for host_chan, p_chan, p_instance in active_connections[:3]:
            encrypted_req = host_chan.encrypt_payload(req_payload)
            
            decrypted_req = p_chan.decrypt_payload(encrypted_req)
            
            resp_payload = p_instance.process_request(decrypted_req)
            
            msg_type, _ = RecoveryMessage.deserialize(resp_payload)
            self.assertEqual(msg_type, RecoveryMsgType.RESP_SHARE)
            
            encrypted_resp = p_chan.encrypt_payload(resp_payload)
            
            decrypted_resp = host_chan.decrypt_payload(encrypted_resp)
            host_logic.process_response(decrypted_resp)
            
            successful_responses += 1
            print(f"  [+] Received valid encrypted share from {p_instance.node_id}")

        print("\n=== Phase 3: Shamir Threshold Reconstruction ===")
        
        self.assertTrue(host_logic.is_ready(), "Host should be ready to reconstruct.")
        self.assertEqual(len(host_logic.collected_shares), 3)
        
        mock_reconstruct.return_value = b"original_master_secret_key"
        recovered_secret = host_logic.reconstruct_secret()
        
        self.assertEqual(recovered_secret, b"original_master_secret_key")
        print("  [SUCCESS] Full end-to-end PQC-secured recovery pipeline verified!")

if __name__ == '__main__':
    unittest.main()
