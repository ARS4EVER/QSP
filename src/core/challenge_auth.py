import os
import time
import json
import threading
from typing import Optional


class ChallengeManager:
    def __init__(self, ttl_seconds: int = 120):
        self.ttl = ttl_seconds
        
        self._cache = {} 
        self._lock = threading.Lock()

    def generate_challenge(self, requester_node_id: str) -> str:
        nonce = os.urandom(32).hex()
        
        with self._lock:
            expires_at = time.monotonic() + self.ttl
            
            self._cache[requester_node_id] = {
                "nonce": nonce,
                "expires_at": expires_at
            }
            
        return nonce

    def verify_and_burn(self, requester_node_id: str, received_nonce: str) -> bool:
        with self._lock:
            if requester_node_id not in self._cache:
                return False
                
            record = self._cache[requester_node_id]
            
            del self._cache[requester_node_id]

            if record["nonce"] != received_nonce:
                return False
            
            if time.monotonic() > record["expires_at"]:
                return False
                
            return True


def build_auth_payload(file_hash: str, threshold: int, nonce: str) -> bytes:
    payload_dict = {
        "file_hash": file_hash,
        "threshold": threshold,
        "nonce": nonce
    }
    
    return json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
