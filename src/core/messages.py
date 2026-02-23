"""
src/core/messages.py
[Phase 3 Refactor] 核心业务层协议定义

简化交互逻辑：底层 SecureChannel 已提供端到端加密和严格的身份认证。
业务层废弃复杂的 3 轮挑战-应答机制，改为极简的"请求-响应"模型。
所有消息通过 JSON 序列化，二进制数据自动进行 Base64 编码。
"""

import json
import base64
from enum import Enum

class RecoveryMsgType(str, Enum):
    """
    精简后的业务消息类型枚举
    """
    # 1. Host -> Participant: 请求恢复
    # Payload 示例: { 
    #   "file_hash": "bytes_b64",     # 请求恢复的文件标识
    #   "timestamp": 1700000000.0,    # 防止重放攻击的时间戳
    #   "host_id": "Node_A",          # 主机标识符
    #   "signature": "bytes_b64"      # (可选) 对该请求的 Dilithium 标准签名
    # }
    REQ_RECOVERY = "REQ_RECOVERY"

    # 2. Participant -> Host: 验证通过，发送 Shamir 份额
    # Payload 示例: { 
    #   "file_hash": "bytes_b64", 
    #   "share_index": 1,             # 份额的 X 坐标
    #   "share_data": "bytes_b64"     # 份额的 Y 坐标数据
    # }
    RESP_SHARE = "RESP_SHARE"

    # 3. 通用错误/拒绝响应
    # Payload 示例: { "code": 403, "msg": "Permission Denied or Signature Invalid" }
    ERROR = "ERROR"


class RecoveryMessage:
    """
    业务消息处理器
    负责将 Python 字典序列化为 JSON 字节流，并自动处理 Base64 编码。
    """
    
    @staticmethod
    def serialize(msg_type: RecoveryMsgType, data: dict) -> bytes:
        """
        打包消息
        Args:
            msg_type: 消息类型 (RecoveryMsgType)
            data: 业务数据字典 (支持 bytes 类型，会自动转为 Base64)
        Returns:
            JSON 编码的 utf-8 字节流
        """
        # 1. 预处理: 将字典中的 bytes 转为 base64 string
        clean_data = {}
        for k, v in data.items():
            if isinstance(v, bytes):
                clean_data[k] = base64.b64encode(v).decode('utf-8')
            else:
                clean_data[k] = v
                
        # 2. 构造完整包
        envelope = {
            "t": msg_type.value, # type
            "d": clean_data      # data
        }
        
        # 3. 转为 JSON bytes
        return json.dumps(envelope).encode('utf-8')

    @staticmethod
    def deserialize(payload_bytes: bytes) -> tuple[RecoveryMsgType, dict]:
        """
        解包消息
        Args:
            payload_bytes: 接收到的 JSON 字节流
        Returns:
            (RecoveryMsgType, data_dict)
            注意: data_dict 中的 base64 string 需要业务层调用 decode_field 显式解码。
        """
        try:
            envelope = json.loads(payload_bytes.decode('utf-8'))
            msg_type = RecoveryMsgType(envelope["t"])
            data = envelope["d"]
            return msg_type, data
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError(f"Invalid recovery message format: {e}")

    @staticmethod
    def decode_field(b64_str: str) -> bytes:
        """辅助工具: 专门用于解码提取 Base64 字段还原为 bytes"""
        return base64.b64decode(b64_str)
