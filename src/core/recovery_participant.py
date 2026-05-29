import os
import json
import base64
import logging

from src.app.app_protocol import AppCmdV2, AppMessageV2, build_challenge_resp
from src.core.challenge_auth import ChallengeManager, build_auth_payload

try:
    from src.crypto_lattice.signer import DilithiumSigner
    verify_signature = DilithiumSigner.verify
except ImportError:
    from src.crypto_lattice.wrapper import lattice_verify as verify_signature


class RecoveryParticipant:
    def __init__(self, p2p_node, vault_crypto):
        self.p2p_node = p2p_node
        self.vault_crypto = vault_crypto
        
        self.challenge_manager = ChallengeManager(ttl_seconds=120)

    def register_handlers(self):
        self.p2p_node.router.register_handler(AppCmdV2.CHALLENGE_REQ, self._handle_challenge_req)
        self.p2p_node.router.register_handler(AppCmdV2.PULL_REQ, self._handle_pull_req)

    def _handle_challenge_req(self, source_id: str, msg: AppMessageV2):
        requester_id = msg.payload.get("requester_id")
        if not requester_id:
            logging.warning(f"[Security] 拦截到缺少 requester_id 的挑战请求")
            return

        nonce = self.challenge_manager.generate_challenge(requester_id)

        resp_msg = build_challenge_resp(self.p2p_node.node_id, nonce)

        if hasattr(self.p2p_node, 'secure_links'):
            found = False
            for addr, link in self.p2p_node.secure_links.items():
                if str(addr) == source_id or addr[0] in source_id:
                    link.send_reliable(resp_msg.encode())
                    found = True
                    break
            
            if found:
                logging.info(f"[Auth] 已向节点 {source_id} 下发防重放挑战码 (Nonce)。")
            else:
                logging.error(f"[Auth] 无法找到到节点 {source_id} 的安全链接")
                self.p2p_node.send_message(requester_id, resp_msg)
        else:
            self.p2p_node.send_message(requester_id, resp_msg)
            logging.info(f"[Auth] 已向节点 {requester_id} 下发防重放挑战码 (Nonce)。")

    def _handle_pull_req(self, source_id: str, msg: AppMessageV2):
        payload = msg.payload
        file_hash = payload.get("file_hash")
        threshold = payload.get("threshold")
        nonce = payload.get("nonce")
        signature_b64 = payload.get("signature")
        requester_pk_b64 = payload.get("public_key")
        requester_id = payload.get("requester_id")

        if not all([file_hash, threshold, nonce, signature_b64, requester_pk_b64, requester_id]):
            self._send_reject(source_id, requester_id, "PULL_REQ 格式不完整，缺少必备字段。")
            return

        if not self.challenge_manager.verify_and_burn(requester_id, nonce):
            logging.warning(f"[Security] 拦截来自 {source_id} 的拉取请求：挑战码无效或已被核销 (重放攻击拦截)！")
            self._send_reject(source_id, requester_id, "挑战码验证失败、已过期或已被消耗，拒绝请求。")
            return

        try:
            signature = base64.b64decode(signature_b64)
            requester_pk = base64.b64decode(requester_pk_b64)

            expected_payload_bytes = build_auth_payload(file_hash, threshold, nonce)

            if not verify_signature(requester_pk, expected_payload_bytes, signature):
                logging.warning(f"[Security] 签名验证失败，节点 {source_id} 的身份不可信！")
                self._send_reject(source_id, requester_id, "抗量子身份签名验证失败，拒绝提取份额！")
                return
        except Exception as e:
            self._send_reject(source_id, requester_id, f"解析加密数据时发生错误: {e}")
            return

        try:
            share_path = self._get_share_path(file_hash)
            if not os.path.exists(share_path):
                self._send_reject(source_id, requester_id, "本地未找到该资产的对应份额。")
                return

            with open(share_path, "rb") as f:
                encrypted_share = f.read()

            decrypted_share = self.vault_crypto.decrypt_chunk(encrypted_share)

            resp_payload = {
                "file_hash": file_hash,
                "share_data": base64.b64encode(decrypted_share).decode('utf-8')
            }
            resp_msg = AppMessageV2(cmd=AppCmdV2.PULL_RESP, sender_id=self.p2p_node.node_id, payload=resp_payload)
            self._send_resp_to_source(source_id, requester_id, resp_msg)
            
            logging.info(f"[Success] 成功响应 {source_id} 的拉取请求，已通过安全信道发送资产切片。")

        except Exception as e:
            logging.error(f"[Error] 本地提取或解密份额时发生致命错误: {e}")
            self._send_reject(source_id, requester_id, "接收端金库读取失败，份额提取终止。")

    def _send_reject(self, source_id: str, requester_id: str, reason: str):
        from src.app.app_protocol import AppCmdV2, AppMessageV2
        msg = AppMessageV2(cmd=AppCmdV2.PULL_REJECT, sender_id=self.p2p_node.node_id, payload={"reason": reason})
        self._send_resp_to_source(source_id, requester_id, msg)
    
    def _send_resp_to_source(self, source_id: str, requester_id: str, msg: AppMessageV2):
        if hasattr(self.p2p_node, 'secure_links'):
            for addr, link in self.p2p_node.secure_links.items():
                if str(addr) == source_id or addr[0] in source_id:
                    link.send_reliable(msg.encode())
                    return
            
            logging.error(f"[Recovery] 无法找到到节点 {source_id} 的安全链接")
            self.p2p_node.send_message(requester_id, msg)
        else:
            self.p2p_node.send_message(requester_id, msg)

    def _get_share_path(self, file_hash: str) -> str:
        from src.config import DATA_DIR
        shares_dir = os.path.join(DATA_DIR, "shares")
        return os.path.join(shares_dir, f"{file_hash}.dat")
