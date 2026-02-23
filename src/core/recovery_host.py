import time
from .messages import RecoveryMessage, RecoveryMsgType
from ..crypto_lattice.signer import DilithiumSigner
from ..secret_sharing.reconstructor import SecretReconstructor

class RecoveryHost:
    def __init__(self, host_id: str, host_sk: bytes, threshold: int):
        self.host_id = host_id
        self.host_sk = host_sk
        self.threshold = threshold
        self.collected_shares = [] 
        self.target_file_hash = None

    def create_recovery_request(self, file_hash: bytes) -> bytes:
        self.target_file_hash = file_hash
        self.collected_shares.clear()
        
        req_data = {
            "file_hash": file_hash,
            "timestamp": time.time(),
            "host_id": self.host_id
        }
        
        msg_to_sign = file_hash + str(req_data["timestamp"]).encode()
        req_data["signature"] = DilithiumSigner.sign(self.host_sk, msg_to_sign)
        
        return RecoveryMessage.serialize(RecoveryMsgType.REQ_RECOVERY, req_data)

    def process_response(self, payload: bytes):
        msg_type, data = RecoveryMessage.deserialize(payload)
        
        if msg_type == RecoveryMsgType.ERROR:
            raise RuntimeError(f"Participant Error: {data.get('msg')}")
            
        if msg_type != RecoveryMsgType.RESP_SHARE:
            raise ValueError(f"Unexpected message type: {msg_type}")
            
        rec_file_hash = RecoveryMessage.decode_field(data["file_hash"])
        if rec_file_hash != self.target_file_hash:
            raise ValueError("Response file hash mismatch.")
            
        share_index = data["share_index"]
        share_data = RecoveryMessage.decode_field(data["share_data"])
        
        if not any(s[0] == share_index for s in self.collected_shares):
            self.collected_shares.append((share_index, share_data))

    def is_ready(self) -> bool:
        return len(self.collected_shares) >= self.threshold

    def reconstruct_secret(self) -> bytes:
        if not self.is_ready():
            raise RuntimeError("Threshold not reached.")
        return SecretReconstructor.reconstruct(self.collected_shares)
