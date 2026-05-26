"""
[Phase 3 Refactor] 核心业务层协议定义

简化交互逻辑：底层 SecureChannel 已提供端到端加密和严格的身份认证。
业务层废弃复杂的 3 轮挑战-应答机制，改为极简的"请求-响应"模型。
所有消息通过 JSON 序列化，二进制数据自动进行 Base64 编码。
"""

import json
import base64
from enum import Enum

class RecoveryMsgType(str, Enum):
    
    REQ_RECOVERY = "REQ_RECOVERY"

    RESP_SHARE = "RESP_SHARE"

    ERROR = "ERROR"


class RecoveryMessage:
    
    @staticmethod
    def serialize(msg_type: RecoveryMsgType, data: dict) -> bytes:
        clean_data = {}
        for k, v in data.items():
            if isinstance(v, bytes):
                clean_data[k] = base64.b64encode(v).decode('utf-8')
            else:
                clean_data[k] = v
                
        envelope = {
            "t": msg_type.value, # type
            "d": clean_data      # data
        }
        
        return json.dumps(envelope).encode('utf-8')

    @staticmethod
    def deserialize(payload_bytes: bytes) -> tuple[RecoveryMsgType, dict]:

        try:
            envelope = json.loads(payload_bytes.decode('utf-8'))
            msg_type = RecoveryMsgType(envelope["t"])
            data = envelope["d"]
            return msg_type, data
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError(f"Invalid recovery message format: {e}")

    @staticmethod
    def decode_field(b64_str: str) -> bytes:
        return base64.b64decode(b64_str)
