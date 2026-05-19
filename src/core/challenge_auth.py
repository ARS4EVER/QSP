import os
import time
import json
import threading
from typing import Optional


class ChallengeManager:
    """
    QSP 挑战-应答管理器 (解决 C8: 依赖时钟同步问题)
    
    该组件用于在 P2P 接收端（份额持有方）安全地管理高熵随机数（Nonce）。
    核心防御特性：
    1. 彻底废弃 time.time()，采用 time.monotonic() 抵御时钟偏移和篡改。
    2. 严格的“阅后即焚 (Burn-after-reading)”机制，使得重放窗口降为 0。
    3. 线程安全的设计，防止高并发下的竞争条件 (Race Condition)。
    """
    def __init__(self, ttl_seconds: int = 120):
        self.ttl = ttl_seconds
        
        self._cache = {} 
        self._lock = threading.Lock()

    def generate_challenge(self, requester_node_id: str) -> str:
        """
        为准备发起恢复请求的节点生成一个唯一的挑战随机数 (Nonce)。
        
        :param requester_node_id: 请求发起方的节点 ID
        :return: 32 字节高熵随机数的 Hex 字符串
        """
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
        验证收到的 Nonce 是否合法，并在验证后【立即销毁】该 Nonce 以防重放。
        
        :param requester_node_id: 请求发起方的节点 ID
        :param received_nonce: 报文中携带的随机数
        :return: 验证通过返回 True，否则返回 False
        """
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
    """
    【架构转换】：构建用于 Dilithium 抗量子签名的最终负载 (Payload)。
    
    废弃了原有的 timestamp 字段，将服务端下发的 nonce 强制绑定到业务数据上。
    请求端对该 Payload 签名，服务端重构该 Payload 验签。
    
    :param file_hash: 试图恢复的资产哈希
    :param threshold: 门限值
    :param nonce: 从服务端获取的挑战随机数
    :return: 确定性序列化后的字节流
    """
    payload_dict = {
        "file_hash": file_hash,
        "threshold": threshold,
        "nonce": nonce
    }
    
    return json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
