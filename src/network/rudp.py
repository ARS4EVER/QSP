import time
import threading
from typing import Dict, List, Tuple


class RUDPConnection:
    """
    可靠 UDP 传输连接
    
    基于 SACK（选择性确认）机制实现可靠传输:
    - 发送端: 维护未确认数据包窗口，支持快速重传
    - 接收端: 维护乱序缓冲区，使用动态 SACK 区间追踪已接收数据
    """
    
    def __init__(self, session_id: int):
        self.session_id = session_id
        
        self.next_seq_num = 1
        self.send_base = 1
        self.unacked_packets: Dict[int, dict] = {}
        self.lock = threading.RLock()
        self.window_condition = threading.Condition(self.lock)
        
        self.rcv_base = 1
        self.out_of_order_buffer: Dict[int, bytes] = {}
        
        self.sack_intervals: List[List[int]] = []

    def receive_data(self, seq: int, payload: bytes) -> Tuple[List[bytes], int, List[Tuple[int, int]]]:
        """处理接收到的数据包，返回可交付数据、确认号和 SACK 区间"""
        deliverable_data = []
        with self.lock:
            if seq == self.rcv_base:
                deliverable_data.append(payload)
                self.rcv_base += 1
                
                while self.rcv_base in self.out_of_order_buffer:
                    deliverable_data.append(self.out_of_order_buffer.pop(self.rcv_base))
                    self.rcv_base += 1
                    
                self._advance_sack_intervals(self.rcv_base)
                
            elif seq > self.rcv_base and seq not in self.out_of_order_buffer:
                self.out_of_order_buffer[seq] = payload
                self._add_seq_to_sack(seq)
            
            sack_blocks = [tuple(x) for x in self.sack_intervals[-10:]]
            return deliverable_data, self.rcv_base - 1, sack_blocks

    def _add_seq_to_sack(self, seq: int):
        """将序列号动态合并到 SACK 区间列表中"""
        if not self.sack_intervals:
            self.sack_intervals.append([seq, seq])
            return
            
        new_intervals = []
        start, end = seq, seq
        inserted = False
        
        for s, e in self.sack_intervals:
            if end + 1 < s:
                if not inserted:
                    new_intervals.append([start, end])
                    inserted = True
                new_intervals.append([s, e])
            elif start - 1 > e:
                new_intervals.append([s, e])
            else:
                start = min(start, s)
                end = max(end, e)
                
        if not inserted:
            new_intervals.append([start, end])
            
        self.sack_intervals = new_intervals

    def _advance_sack_intervals(self, rcv_base: int):
        """当接收基线推进时，修剪已过期 SACK 区间"""
        if not self.sack_intervals:
            return
            
        new_intervals = []
        for s, e in self.sack_intervals:
            if e < rcv_base:
                continue
            elif s < rcv_base:
                if rcv_base <= e:
                    new_intervals.append([rcv_base, e])
            else:
                new_intervals.append([s, e])
                
        self.sack_intervals = new_intervals

    def _calculate_sack_blocks(self) -> List[Tuple[int, int]]:
        """返回最近的 SACK 区间列表（兼容性方法）"""
        return [tuple(x) for x in self.sack_intervals[-10:]]

    def track_sent_packet(self, seq: int, payload: bytes):
        """追踪已发送的数据包"""
        with self.lock:
            self.unacked_packets[seq] = {
                'payload': payload,
                'timestamp': time.time(),
                'sack_count': 0
            }
            if seq >= self.next_seq_num:
                self.next_seq_num = seq + 1

    def handle_sack(self, ack: int, sack_blocks: List[Tuple[int, int]]) -> Tuple[List[Tuple[int, bytes]], float]:
        """处理 SACK 确认，返回需要快速重传的数据包列表和 RTT 样本"""
        fast_retransmit_list = []
        rtt_sample = -1.0
        current_time = time.time()
        packets_cleared = False 
        
        with self.lock:
            if ack >= self.send_base:
                self.send_base = ack + 1
                keys_to_remove = [s for s in self.unacked_packets.keys() if s <= ack]
                for k in keys_to_remove:
                    rtt_sample = current_time - self.unacked_packets[k]['timestamp']
                    del self.unacked_packets[k]
                    packets_cleared = True
                    
            max_sacked_seq = ack
            for start_seq, end_seq in sack_blocks:
                max_sacked_seq = max(max_sacked_seq, end_seq)
                for seq in range(start_seq, end_seq + 1):
                    if seq in self.unacked_packets:
                        rtt_sample = current_time - self.unacked_packets[seq]['timestamp']
                        del self.unacked_packets[seq]
                        packets_cleared = True
                        
            for seq, info in self.unacked_packets.items():
                if seq < max_sacked_seq:
                    info['sack_count'] += 1
                    if info['sack_count'] >= 3:
                        fast_retransmit_list.append((seq, info['payload']))
                        info['sack_count'] = 0 
                        info['timestamp'] = current_time
                        
            if packets_cleared:
                self.window_condition.notify_all()
                        
        return fast_retransmit_list, rtt_sample

    def wait_for_window(self, max_packets: int):
        """等待拥塞窗口可用"""
        with self.window_condition:
            while len(self.unacked_packets) >= max_packets:
                self.window_condition.wait(timeout=0.1)
