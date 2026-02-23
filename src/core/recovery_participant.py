import time
from .messages import RecoveryMessage, RecoveryMsgType
from ..crypto_lattice.signer import DilithiumSigner

class RecoveryParticipant:
    def __init__(self, node_id: str, trusted_hosts: dict):
        self.node_id = node_id
        self.trusted_hosts = trusted_hosts
        self.share_storage = {}

    def store_share(self, file_hash: bytes, share_index: int, share_data: bytes):
        self.share_storage[file_hash] = (share_index, share_data)

    def process_request(self, payload: bytes) -> bytes:
        try:
            msg_type, data = RecoveryMessage.deserialize(payload)
            
            if msg_type != RecoveryMsgType.REQ_RECOVERY:
                return self._build_error("Invalid message type")

            host_id = data.get("host_id")
            if host_id not in self.trusted_hosts:
                return self._build_error("Unknown host")

            file_hash = RecoveryMessage.decode_field(data["file_hash"])
            timestamp = data.get("timestamp", 0)
            signature = RecoveryMessage.decode_field(data["signature"])

            if time.time() - timestamp > 60:
                return self._build_error("Request expired")

            msg_to_verify = file_hash + str(timestamp).encode()
            host_pk = self.trusted_hosts[host_id]
            
            if not DilithiumSigner.verify(host_pk, msg_to_verify, signature):
                return self._build_error("Signature verification failed")

            if file_hash not in self.share_storage:
                return self._build_error("Share not found")

            share_index, share_data = self.share_storage[file_hash]
            
            resp_data = {
                "file_hash": file_hash,
                "share_index": share_index,
                "share_data": share_data
            }
            return RecoveryMessage.serialize(RecoveryMsgType.RESP_SHARE, resp_data)

        except Exception as e:
            return self._build_error(str(e))

    def _build_error(self, error_msg: str) -> bytes:
        return RecoveryMessage.serialize(
            RecoveryMsgType.ERROR, 
            {"code": 403, "msg": error_msg}
        )
