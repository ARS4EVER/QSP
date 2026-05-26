"""
src/app/app_protocol.py
[Application Phase 1] 应用层传输协议定义
负责业务指令与二进制数据（如 Shamir 份额）的 JSON/Base64 序列化与反序列化。
"""

import json
import struct
import base64
from enum import IntEnum, Enum
from dataclasses import dataclass
from typing import Any, Dict, Optional

class AppCmd(str, Enum):
    SHARE_PUSH = "SHARE_PUSH"
    PULL_REQ = "PULL_REQ"
    PULL_RESP = "PULL_RESP"
    ERROR = "ERROR"


class AppMessage:

    def __init__(self, 
                 cmd: AppCmd, 
                 file_hash: str, 
                 share_index: Optional[int] = None, 
                 share_data: Optional[bytes] = None,
                 error_msg: Optional[str] = None,
                 chunk_index: int = 0,
                 total_chunks: int = 1):
        self.cmd = cmd
        self.file_hash = file_hash
        self.share_index = share_index
        self.share_data = share_data
        self.error_msg = error_msg
        self.chunk_index = chunk_index
        self.total_chunks = total_chunks

    def pack(self) -> bytes:
        payload_dict: Dict[str, Any] = {
            "cmd": self.cmd.value,
            "file_hash": self.file_hash,
            "chunk_index": self.chunk_index,
            "total_chunks": self.total_chunks
        }

        if self.share_index is not None:
            payload_dict["share_index"] = self.share_index

        if self.share_data is not None:
            payload_dict["share_data_b64"] = base64.b64encode(self.share_data).decode('utf-8')

        if self.error_msg is not None:
            payload_dict["error_msg"] = self.error_msg

        json_str = json.dumps(payload_dict)
        return json_str.encode('utf-8')

    @classmethod
    def unpack(cls, data: bytes) -> "AppMessage":
        try:
            json_str = data.decode('utf-8')
            payload_dict = json.loads(json_str)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"应用层数据格式损坏，无法解析 JSON: {e}")

        if "cmd" not in payload_dict:
            raise ValueError("非法的应用层消息：缺失 'cmd' 字段。")
        if "file_hash" not in payload_dict:
            raise ValueError("非法的应用层消息：缺失 'file_hash' 字段。")

        try:
            cmd = AppCmd(payload_dict["cmd"])
        except ValueError:
            raise ValueError(f"未知的应用层指令: {payload_dict['cmd']}")

        file_hash = payload_dict["file_hash"]
        share_index = payload_dict.get("share_index")
        error_msg = payload_dict.get("error_msg")
        chunk_index = payload_dict.get("chunk_index", 0)
        total_chunks = payload_dict.get("total_chunks", 1)

        share_data = None
        if "share_data_b64" in payload_dict:
            try:
                share_data = base64.b64decode(payload_dict["share_data_b64"])
            except Exception as e:
                raise ValueError(f"Base64 解码份额数据失败: {e}")

        return cls(
            cmd=cmd,
            file_hash=file_hash,
            share_index=share_index,
            share_data=share_data,
            error_msg=error_msg,
            chunk_index=chunk_index,
            total_chunks=total_chunks
        )


class AppCmdV2(IntEnum):
    PING = 1
    PONG = 2
    SHARE_PUSH = 3
    SHARE_ACK = 4
    PULL_REQ = 5
    PULL_RESP = 6
    PULL_REJECT = 7
    CHALLENGE_REQ = 10
    CHALLENGE_RESP = 11


@dataclass
class AppMessageV2:
    cmd: AppCmdV2
    sender_id: str
    payload: Dict[str, Any]

    def encode(self) -> bytes:
        data = {
            "cmd": self.cmd.value,
            "sender_id": self.sender_id,
            "payload": self.payload
        }
        return json.dumps(data, separators=(',', ':')).encode('utf-8')

    @classmethod
    def decode(cls, data: bytes) -> 'AppMessageV2':
        try:
            parsed = json.loads(data.decode('utf-8'))
            
            if not all(k in parsed for k in ("cmd", "sender_id", "payload")):
                raise ValueError("报文缺少必备字段 (cmd, sender_id, payload)")
                
            cmd_val = parsed["cmd"]
            if not any(cmd_val == item.value for item in AppCmdV2):
                raise ValueError(f"未知的指令代码: {cmd_val}")
                
            return cls(
                cmd=AppCmdV2(cmd_val),
                sender_id=parsed["sender_id"],
                payload=parsed["payload"]
            )
        except json.JSONDecodeError as e:
            raise ValueError(f"报文解析失败，非法的 JSON 格式: {e}")
        except Exception as e:
            raise ValueError(f"报文结构异常: {e}")


def build_challenge_req(sender_id: str) -> AppMessageV2:
    return AppMessageV2(
        cmd=AppCmdV2.CHALLENGE_REQ,
        sender_id=sender_id,
        payload={"requester_id": sender_id}
    )

def build_challenge_resp(sender_id: str, nonce: str) -> AppMessageV2:
    return AppMessageV2(
        cmd=AppCmdV2.CHALLENGE_RESP,
        sender_id=sender_id,
        payload={"nonce": nonce}
    )
