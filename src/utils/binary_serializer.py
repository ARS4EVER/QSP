import msgpack
import zlib
from typing import Any, Dict, Optional


class BinarySerializer:
    
    @staticmethod
    def serialize(data: Dict[str, Any], compress: bool = True) -> bytes:
        packed = msgpack.packb(data, use_bin_type=True)
        if compress:
            packed = zlib.compress(packed, level=3)
        return packed

    @staticmethod
    def deserialize(payload_bytes: bytes, compressed: bool = True) -> Dict[str, Any]:
        if compressed:
            payload_bytes = zlib.decompress(payload_bytes)
        return msgpack.unpackb(payload_bytes, raw=False)

    @staticmethod
    def serialize_with_header(data: Dict[str, Any], msg_type: int, compress: bool = True) -> bytes:
        header = msg_type.to_bytes(1, byteorder='big')
        body = BinarySerializer.serialize(data, compress)
        return header + body

    @staticmethod
    def deserialize_with_header(payload_bytes: bytes, compressed: bool = True) -> tuple[int, Dict[str, Any]]:
        if len(payload_bytes) < 1:
            raise ValueError("Payload too short")
        msg_type = payload_bytes[0]
        body = payload_bytes[1:]
        data = BinarySerializer.deserialize(body, compressed)
        return msg_type, data