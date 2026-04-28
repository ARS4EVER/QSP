import struct
import time
from enum import IntEnum
from typing import List, Tuple, Optional, Dict, Any


class PacketType(IntEnum):
    # --- NAT 穿透与维持信令 ---
    HOLEPUNCH = 0x01
    HOLEPUNCH_ACK = 0x02
    KEEPALIVE = 0x03      # <--- 新增：心跳保活探测包
    
    # --- 抗量子安全握手 ---
    HANDSHAKE_INIT = 0x10
    HANDSHAKE_RESP = 0x11
    
    # --- 高带宽可靠传输 (RUDP) ---
    DATA = 0x20
    ACK = 0x21
    SACK = 0x22
    FIN = 0x2F


class QSPProtocol:
    MAGIC = 0x5153
    VERSION = 0x01
    HEADER_FORMAT = "!H B B I I I Q H"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    @classmethod
    def pack(cls, pkt_type: PacketType, seq: int, payload: bytes, ack: int = 0, session_id: int = 0, timestamp: Optional[int] = None) -> bytes:
        if timestamp is None:
            timestamp = int(time.time() * 1_000_000)
            
        payload_len = len(payload)
        
        header = struct.pack(
            cls.HEADER_FORMAT,
            cls.MAGIC,
            cls.VERSION,
            pkt_type.value,
            session_id,
            seq,
            ack,
            timestamp,
            payload_len
        )
        return header + payload

    @classmethod
    def unpack(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Packet size ({len(data)}) is smaller than header size ({cls.HEADER_SIZE}).")

        magic, version, type_val, session_id, seq, ack, timestamp, payload_len = struct.unpack(
            cls.HEADER_FORMAT, data[:cls.HEADER_SIZE]
        )

        if magic != cls.MAGIC:
            raise ValueError(f"Invalid magic number: {hex(magic)}")
        if version != cls.VERSION:
            raise ValueError(f"Unsupported protocol version: {version}")
            
        try:
            pkt_type = PacketType(type_val)
        except ValueError:
            raise ValueError(f"Unknown packet type: {type_val}")

        expected_total_len = cls.HEADER_SIZE + payload_len
        if len(data) < expected_total_len:
            raise ValueError(f"Incomplete packet payload. Expected {payload_len} bytes.")

        payload = data[cls.HEADER_SIZE:expected_total_len]
        
        return {
            'type': pkt_type,
            'session_id': session_id,
            'seq': seq,
            'ack': ack,
            'timestamp': timestamp,
            'payload': payload
        }

    @classmethod
    def build_sack_payload(cls, sack_blocks: List[Tuple[int, int]]) -> bytes:
        payload = bytearray()
        for start_seq, end_seq in sack_blocks:
            payload.extend(struct.pack("!I I", start_seq, end_seq))
        return bytes(payload)

    @classmethod
    def parse_sack_blocks(cls, payload: bytes) -> List[Tuple[int, int]]:
        blocks = []
        for i in range(0, len(payload), 8):
            if i + 8 <= len(payload):
                start_seq, end_seq = struct.unpack("!I I", payload[i:i+8])
                blocks.append((start_seq, end_seq))
        return blocks
