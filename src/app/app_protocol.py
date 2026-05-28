"""
应用层混合协议定义

实现 TLV 风格的混合协议：
- 结构化控制指令使用 JSON（便于扩展）
- 大体积文件块直接作为二进制尾部（Raw Payload）

消除应用层对二进制文件块的 Base64 编码与 JSON 序列化开销
"""

import json
import struct
import base64
from enum import IntEnum, Enum
from typing import Any, Dict, Optional


class AppCmd(str, Enum):
    """应用层命令枚举（旧版本兼容）"""
    SHARE_PUSH = "SHARE_PUSH"
    PULL_REQ = "PULL_REQ"
    PULL_RESP = "PULL_RESP"
    ERROR = "ERROR"


class AppMessage:
    """
    应用层消息（旧版本）
    
    JSON 格式，包含命令、文件哈希、份额数据等字段
    """

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
        """序列化为 JSON 字节"""
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
        """从 JSON 字节反序列化"""
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
    """应用层命令枚举 V2（高性能版本）"""
    PING = 1
    PONG = 2
    SHARE_PUSH = 3
    SHARE_ACK = 4
    PULL_REQ = 5
    PULL_RESP = 6
    PULL_REJECT = 7
    MANIFEST_KEY_EXCHANGE = 8
    CHALLENGE_REQ = 10
    CHALLENGE_RESP = 11


class AppMessageV2:
    """
    应用层消息 V2（高性能混合协议）
    
    格式: [4字节 Header长度] + [JSON Header] + [二进制 Raw Payload]
    """

    def __init__(self, cmd: AppCmdV2, sender_id: str, payload: dict, raw_payload: bytes = b""):
        self.cmd = cmd
        self.sender_id = sender_id
        self.payload = payload or {}
        self.raw_payload = raw_payload  # 大体积文件切片

    def encode(self) -> bytes:
        """
        混合序列化
        
        消除大体积数据的 Base64 转换开销
        """
        cmd_val = self.cmd.value if isinstance(self.cmd, Enum) else self.cmd
        header_dict = {
            "cmd": cmd_val,
            "sender_id": self.sender_id,
            "payload": self.payload
        }
        
        header_bytes = json.dumps(header_dict).encode('utf-8')
        header_length = len(header_bytes)
        
        return struct.pack('!I', header_length) + header_bytes + self.raw_payload

    @classmethod
    def decode(cls, data: bytes):
        """反序列化，支持协议版本兼容"""
        if not data:
            raise ValueError("[AppProtocol] 收到空数据包")
            
        # 兼容性分支1：老版本协议的 payload 直接是一个 JSON 字符串，以 '{' 开头
        if data[0] == ord('{'):
            header_dict = json.loads(data.decode('utf-8'))
            raw_payload = b""
            payload = header_dict.get("payload", {})
            if "share_data_b64" in payload:
                raw_payload = base64.b64decode(payload["share_data_b64"])
                del payload["share_data_b64"]
                header_dict["payload"] = payload
        else:
            if len(data) < 4:
                raise ValueError("[AppProtocol] 数据包残缺，无法读取 Header 长度")
                
            header_length = struct.unpack('!I', data[:4])[0]
            if len(data) < 4 + header_length:
                raise ValueError("[AppProtocol] 数据包长度异常，Header 截断")
                
            header_bytes = data[4 : 4 + header_length]
            header_dict = json.loads(header_bytes.decode('utf-8'))
            raw_payload = data[4 + header_length :]
            
        cmd_val = header_dict.get("cmd")
        if isinstance(cmd_val, int):
            cmd = AppCmdV2(cmd_val)
        else:
            for cmd_enum in AppCmdV2:
                if cmd_enum.name == cmd_val or str(cmd_enum.value) == str(cmd_val):
                    cmd = cmd_enum
                    break
            else:
                raise ValueError(f"未知的指令代码: {cmd_val}")
                
        return cls(
            cmd=cmd,
            sender_id=header_dict.get("sender_id", ""),
            payload=header_dict.get("payload", {}),
            raw_payload=raw_payload
        )


def build_challenge_req(sender_id: str) -> AppMessageV2:
    """构建挑战请求消息"""
    return AppMessageV2(
        cmd=AppCmdV2.CHALLENGE_REQ,
        sender_id=sender_id,
        payload={"requester_id": sender_id}
    )


def build_challenge_resp(sender_id: str, nonce: str) -> AppMessageV2:
    """构建挑战响应消息"""
    return AppMessageV2(
        cmd=AppCmdV2.CHALLENGE_RESP,
        sender_id=sender_id,
        payload={"nonce": nonce}
    )
