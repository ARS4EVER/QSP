"""
src/network/rudp.py
[Phase 3 Refactor] 可靠 UDP 传输核心引擎
彻底移除冗余的 RUDPSocket 包装，仅保留 SACK 滑动窗口与快速重传逻辑，交由 SecureLink 统一调度。
"""

import time
import threading
from typing import Dict, List, Tuple

class RUDPConnection:
    """
    维护单个 P2P 节点的可靠传输上下文（滑动窗口与 SACK 状态机）
    """
    def __init__(self, session_id: int):
        self.session_id = session_id
        
        self.next_seq_num = 1
        self.send_base = 1
        self.unacked_packets: Dict[int, dict] = {}
        self.lock = threading.RLock()
        
        self.rcv_base = 1
        self.out_of_order_buffer: Dict[int, bytes] = {}

    def receive_data(self, seq: int, payload: bytes) -> Tuple[List[bytes], int, List[Tuple[int, int]]]:
        deliverable_data = []
        with self.lock:
            if seq == self.rcv_base:
                deliverable_data.append(payload)
                self.rcv_base += 1
                
                while self.rcv_base in self.out_of_order_buffer:
                    deliverable_data.append(self.out_of_order_buffer.pop(self.rcv_base))
                    self.rcv_base += 1
            elif seq > self.rcv_base:
                self.out_of_order_buffer[seq] = payload
            
            sack_blocks = self._calculate_sack_blocks()
            return deliverable_data, self.rcv_base - 1, sack_blocks

    def _calculate_sack_blocks(self) -> List[Tuple[int, int]]:
        if not self.out_of_order_buffer:
            return []
            
        seqs = sorted(self.out_of_order_buffer.keys())
        blocks = []
        start = seqs[0]
        end = seqs[0]
        
        for i in range(1, len(seqs)):
            if seqs[i] == end + 1:
                end = seqs[i]
            else:
                blocks.append((start, end))
                start = seqs[i]
                end = seqs[i]
        blocks.append((start, end))
        
        return blocks[-10:]

    def track_sent_packet(self, seq: int, payload: bytes):
        with self.lock:
            self.unacked_packets[seq] = {
                'payload': payload,
                'timestamp': time.time(),
                'sack_count': 0
            }
            if seq >= self.next_seq_num:
                self.next_seq_num = seq + 1

    def handle_sack(self, ack: int, sack_blocks: List[Tuple[int, int]]) -> Tuple[List[Tuple[int, bytes]], float]:
        fast_retransmit_list = []
        rtt_sample = -1.0
        current_time = time.time()
        
        with self.lock:
            if ack >= self.send_base:
                self.send_base = ack + 1
                keys_to_remove = [s for s in self.unacked_packets.keys() if s <= ack]
                for k in keys_to_remove:
                    rtt_sample = current_time - self.unacked_packets[k]['timestamp']
                    del self.unacked_packets[k]
                    
            max_sacked_seq = ack
            for start_seq, end_seq in sack_blocks:
                max_sacked_seq = max(max_sacked_seq, end_seq)
                for seq in range(start_seq, end_seq + 1):
                    if seq in self.unacked_packets:
                        rtt_sample = current_time - self.unacked_packets[seq]['timestamp']
                        del self.unacked_packets[seq]
                        
            for seq, info in self.unacked_packets.items():
                if seq < max_sacked_seq:
                    info['sack_count'] += 1
                    if info['sack_count'] >= 3:
                        fast_retransmit_list.append((seq, info['payload']))
                        info['sack_count'] = 0 
                        info['timestamp'] = current_time
                        
        return fast_retransmit_list, rtt_sample
