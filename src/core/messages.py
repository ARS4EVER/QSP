"""
[Phase 3 Refactor] 核心业务层协议定义

简化交互逻辑：底层 SecureChannel 已提供端到端加密和严格的身份认证。
业务层废弃复杂的 3 轮挑战-应答机制，改为极简的"请求-响应"模型。

[Performance Optimization] 使用 MessagePack 替代 JSON/Base64，消除 33% 数据膨胀
"""

import json
import base64
from enum import Enum
from src.utils.binary_serializer import BinarySerializer


class RecoveryMsgType(Enum):
    
    REQ_RECOVERY = 0x01
    RESP_SHARE = 0x02
    ERROR = 0xFF


class RecoveryMessage:
    
    USE_BINARY = True
    
    @staticmethod
    def serialize(msg_type: RecoveryMsgType, data: dict) -> bytes:
        if RecoveryMessage.USE_BINARY:
            envelope = {
                "t": msg_type.value,
                "d": data
            }
            return BinarySerializer.serialize_with_header(envelope, msg_type.value)
        else:
            clean_data = {}
            for k, v in data.items():
                if isinstance(v, bytes):
                    clean_data[k] = base64.b64encode(v).decode('utf-8')
                else:
                    clean_data[k] = v
                    
            envelope = {
                "t": msg_type.value,
                "d": clean_data
            }
            
            return json.dumps(envelope).encode('utf-8')

    @staticmethod
    def deserialize(payload_bytes: bytes) -> tuple[RecoveryMsgType, dict]:
        if RecoveryMessage.USE_BINARY:
            try:
                msg_type_val, envelope = BinarySerializer.deserialize_with_header(payload_bytes)
                msg_type = RecoveryMsgType(msg_type_val)
                data = envelope.get("d", {})
                return msg_type, data
            except Exception as e:
                raise ValueError(f"Invalid binary recovery message format: {e}")
        else:
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
