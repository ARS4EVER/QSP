import msgpack
import zlib
from typing import Any, Dict, Optional


class BinarySerializer:
    """
    二进制序列化器
    
    使用 MessagePack + zlib 压缩实现高效二进制序列化
    支持带消息头的封装格式
    """
    
    @staticmethod
    def serialize(data: Dict[str, Any], compress: bool = True) -> bytes:
        """将字典序列化为二进制（可选压缩）"""
        packed = msgpack.packb(data, use_bin_type=True)
        if compress:
            packed = zlib.compress(packed, level=3)
        return packed

    @staticmethod
    def deserialize(payload_bytes: bytes, compressed: bool = True) -> Dict[str, Any]:
        """反序列化二进制数据（可选解压缩）"""
        if compressed:
            payload_bytes = zlib.decompress(payload_bytes)
        return msgpack.unpackb(payload_bytes, raw=False)

    @staticmethod
    def serialize_with_header(data: Dict[str, Any], msg_type: int, compress: bool = True) -> bytes:
        """序列化并添加 1 字节消息类型头"""
        header = msg_type.to_bytes(1, byteorder='big')
        body = BinarySerializer.serialize(data, compress)
        return header + body

    @staticmethod
    def deserialize_with_header(payload_bytes: bytes, compressed: bool = True) -> tuple[int, Dict[str, Any]]:
        """从带消息头的数据中提取类型和内容"""
        if len(payload_bytes) < 1:
            raise ValueError("Payload too short")
        msg_type = payload_bytes[0]
        body = payload_bytes[1:]
        data = BinarySerializer.deserialize(body, compressed)
        return msg_type, data