import os
import time
import json
import threading
from typing import Optional


class ChallengeManager:
    """
    防重放挑战管理器
    
    使用一次性随机数（Nonce）防止恶意节点重放旧请求
    每次生成的挑战码有 TTL 限制，超时后自动失效
    """
    
    def __init__(self, ttl_seconds: int = 120):
        self.ttl = ttl_seconds
        self._cache = {}  # {node_id: {nonce, expires_at}}
        self._lock = threading.Lock()

    def generate_challenge(self, requester_node_id: str) -> str:
        """生成挑战码并存储到缓存"""
        nonce = os.urandom(32).hex()
        with self._lock:
            expires_at = time.monotonic() + self.ttl
            self._cache[requester_node_id] = {
                "nonce": nonce,
                "expires_at": expires_at
            }
        return nonce

    def verify_and_burn(self, requester_node_id: str, received_nonce: str) -> bool:
        """
        验证挑战码并销毁（一次性使用）
        
        返回 True 仅当：Nonce 匹配 且 未过期
        """
        with self._lock:
            if requester_node_id not in self._cache:
                return False
            record = self._cache[requester_node_id]
            del self._cache[requester_node_id]  # 核销（burn）

            if record["nonce"] != received_nonce:
                return False
            if time.monotonic() > record["expires_at"]:
                return False
            return True


def build_auth_payload(file_hash: str, threshold: int, nonce: str) -> bytes:
    """构建待签名载荷（用于抗量子签名验证）"""
    payload_dict = {
        "file_hash": file_hash,
        "threshold": threshold,
        "nonce": nonce
    }
    return json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
