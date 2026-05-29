"""
src/network/rudp.py
可靠 UDP 传输核心引擎
优化：动态区间维护机制，消除 O(N log N) 排序瓶颈
"""
import time
import threading
from typing import Dict, List, Tuple

class RUDPConnection:
    def __init__(self, session_id: int):
        self.session_id = session_id
        
        # 发送端状态
        self.next_seq_num = 1
        self.send_base = 1
        self.unacked_packets: Dict[int, dict] = {}
        self.lock = threading.RLock()
        self.window_condition = threading.Condition(self.lock)
        
        # 接收端状态
        self.rcv_base = 1
        self.out_of_order_buffer: Dict[int, bytes] = {}
        
        # 【新增】动态维护的连续 SACK 区间列表，替代原先 O(N log N) 的字典全量排序
        self.sack_intervals: List[List[int]] = []

    def receive_data(self, seq: int, payload: bytes) -> Tuple[List[bytes], int, List[Tuple[int, int]]]:
        deliverable_data = []
        with self.lock:
            if seq == self.rcv_base:
                deliverable_data.append(payload)
                self.rcv_base += 1
                
                while self.rcv_base in self.out_of_order_buffer:
                    deliverable_data.append(self.out_of_order_buffer.pop(self.rcv_base))
                    self.rcv_base += 1
                    
                # 推进基础序列号后，清理过期区间
                self._advance_sack_intervals(self.rcv_base)
                
            elif seq > self.rcv_base and seq not in self.out_of_order_buffer:
                self.out_of_order_buffer[seq] = payload
                # O(K) 复杂度的动态区间合并
                self._add_seq_to_sack(seq)
            
            # 返回最新的至多 10 个 SACK 区间供发送端快速重传
            sack_blocks = [tuple(x) for x in self.sack_intervals[-10:]]
            return deliverable_data, self.rcv_base - 1, sack_blocks

    def _add_seq_to_sack(self, seq: int):
        """
        【核心优化】将新到达的乱序序列号无缝融入现有区间
        时间复杂度：O(K)，K 为现有区间数量（通常 < 10）
        """
        if not self.sack_intervals:
            self.sack_intervals.append([seq, seq])
            return
            
        new_intervals = []
        start, end = seq, seq
        inserted = False
        
        for s, e in self.sack_intervals:
            # 新区间完全在当前区间左侧
            if end + 1 < s:
                if not inserted:
                    new_intervals.append([start, end])
                    inserted = True
                new_intervals.append([s, e])
            # 新区间完全在当前区间右侧
            elif start - 1 > e:
                new_intervals.append([s, e])
            # 存在交集或物理相连，执行合并
            else:
                start = min(start, s)
                end = max(end, e)
                
        if not inserted:
            new_intervals.append([start, end])
            
        self.sack_intervals = new_intervals

    def _advance_sack_intervals(self, rcv_base: int):
        """
        当接收基线推进时，修剪落后的 SACK 区间，防止内存泄漏。
        """
        if not self.sack_intervals:
            return
            
        new_intervals = []
        for s, e in self.sack_intervals:
            # 整个区间已过期，丢弃
            if e < rcv_base:
                continue
            # 区间部分过期，截断左侧
            elif s < rcv_base:
                if rcv_base <= e:
                    new_intervals.append([rcv_base, e])
            # 区间完全在基线之后，保留
            else:
                new_intervals.append([s, e])
                
        self.sack_intervals = new_intervals

    def _calculate_sack_blocks(self) -> List[Tuple[int, int]]:
        """
        【保留】兼容性方法，优先使用新的 sack_intervals
        """
        return [tuple(x) for x in self.sack_intervals[-10:]]

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
        with self.window_condition:
            while len(self.unacked_packets) >= max_packets:
                self.window_condition.wait(timeout=0.1)
