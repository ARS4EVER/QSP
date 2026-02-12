# src/network/rudp.py

import socket
import threading
import struct
import queue
import random
import time

class ReliableUDPSocket:
    """
    增强版可靠 UDP (RUDP) 实现 - 支持多对等点 (Server Mode) 适配版
    """
    
    MTU = 1024
    HEADER_SIZE = 12 
    TIMEOUT = 0.5
    MAX_RETRIES = 10

    def __init__(self, bind_port=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 设置 socket 缓冲区大小，防止高并发丢包
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        self.sock.bind(('0.0.0.0', bind_port))
        
        self.peer_addr = None # 默认对等点 (Client模式主要使用)
        self.recv_queue = queue.Queue()
        
        # 发送控制相关
        self.ack_event = threading.Event()
        self.expected_ack = None 
        self.expected_ack_addr = None # [新增] 记录期望接收 ACK 的地址
        
        self.processed_packets = {} 
        
        self.running = False
        self.thread = None 

    def start(self):
        """显式启动接收线程"""
        if self.running:
            return 
        
        self.running = True
        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()
        print(f"[RUDP] Listening thread started on port {self.sock.getsockname()[1]}")

    def set_peer(self, ip, port):
        self.peer_addr = (ip, int(port))

    def send(self, data_bytes, target_addr=None):
        """
        [修改] 发送数据，支持指定目标地址
        :param target_addr: (ip, port) 元组。如果为 None，则发送给 set_peer 设置的地址
        """
        # 确定发送目标: 优先使用参数传入的地址，否则使用默认 peer_addr
        dest = target_addr if target_addr else self.peer_addr
        
        if not dest:
            raise ValueError("Destination address not set. Pass target_addr or use set_peer().")
            
        msg_id = random.getrandbits(32)
        total_len = len(data_bytes)
        chunk_size = self.MTU - self.HEADER_SIZE
        num_chunks = (total_len + chunk_size - 1) // chunk_size
        if num_chunks == 0: num_chunks = 1
        
        for i in range(num_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, total_len)
            chunk = data_bytes[start:end]
            
            # 打包: ID(4) | ChunkIdx(4) | TotalChunks(4) | Data(...)
            header = struct.pack(">III", msg_id, i, num_chunks)
            packet = header + chunk
            
            # [修改] 传入确定的目标地址
            if not self._send_chunk_reliable(packet, msg_id, i, dest):
                return False
        return True

    def _send_chunk_reliable(self, packet, msg_id, chunk_idx, dest_addr):
        self.expected_ack = (msg_id, chunk_idx)
        self.expected_ack_addr = dest_addr # [新增] 记录我们发给了谁
        self.ack_event.clear()
        
        # 加上协议头 DAT
        final_packet = b'DAT' + packet
        
        for attempt in range(self.MAX_RETRIES):
            self.sock.sendto(final_packet, dest_addr)
            if self.ack_event.wait(self.TIMEOUT):
                return True
            # 指数退避 (可选，暂不启用以保证低延迟)
            
        print(f"[RUDP] Connection Lost. Failed to send {msg_id}:{chunk_idx} to {dest_addr}")
        return False

    def recv(self):
        """
        [修改] 从队列获取数据
        Returns:
            (data, addr): 数据内容和来源地址的元组
        """
        return self.recv_queue.get()

    def _listen_loop(self):
        # [修改] key 改为 (addr, msg_id) 以支持多客户端并发发送
        buffer_pool = {} 
        meta_pool = {}
        
        print("[RUDP] Listener loop running...")
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                
                # 忽略打洞包
                if data == b'PUNCH': continue

                # 处理 ACK
                if data.startswith(b'ACK'):
                    if len(data) >= 11: 
                        payload = data[3:]
                        ack_msg_id, ack_chunk_idx = struct.unpack(">II", payload)
                        
                        # 检查是否是我们正在等待的 ACK
                        if self.expected_ack == (ack_msg_id, ack_chunk_idx):
                            # [修改] 验证来源地址
                            # 宽松验证：IP相同 或者 端口相同 (适应NAT)
                            # 或者如果我们没有设置 expected_ack_addr (兼容旧逻辑)，则通过
                            expected_dest = self.expected_ack_addr
                            
                            is_valid_source = False
                            if expected_dest:
                                if addr == expected_dest or addr[0] == expected_dest[0]:
                                    is_valid_source = True
                            else:
                                # Fallback: 如果没记录发送目标，默认信任 (兼容旧代码逻辑)
                                is_valid_source = True

                            if is_valid_source:
                                self.ack_event.set()
                    continue
                
                # 处理 数据包
                if data.startswith(b'DAT'):
                    payload = data[3:]
                    if len(payload) < 12: continue
                    msg_id, idx, total = struct.unpack(">III", payload[:12])
                    content = payload[12:]
                    
                    # 1. 立即回复 ACK
                    ack_packet = b'ACK' + struct.pack(">II", msg_id, idx)
                    self.sock.sendto(ack_packet, addr)
                    
                    # 更新默认对方地址 (仅在 Client 模式下或首次连接有意义)
                    if not self.peer_addr: self.peer_addr = addr 
                    
                    # 2. 去重 (key 增加 addr 防止 ID 冲突)
                    dedup_key = (addr, msg_id, idx)
                    if dedup_key in self.processed_packets: continue
                    self.processed_packets[dedup_key] = time.time()
                    
                    # 3. 组装逻辑 (Buffer Key 增加 addr)
                    pool_key = (addr, msg_id)
                    
                    if pool_key not in buffer_pool:
                        buffer_pool[pool_key] = {}
                        meta_pool[pool_key] = total
                    
                    if idx not in buffer_pool[pool_key]:
                        buffer_pool[pool_key][idx] = content
                        
                    # 检查是否集齐
                    if len(buffer_pool[pool_key]) == meta_pool[pool_key]:
                        # 按顺序拼接
                        full_data = b"".join([buffer_pool[pool_key][i] for i in range(meta_pool[pool_key])])
                        
                        # [修改] 将 (data, addr) 放入队列，以便上层区分来源
                        self.recv_queue.put((full_data, addr))
                        
                        # 清理缓存
                        del buffer_pool[pool_key]
                        del meta_pool[pool_key]
                        
                        # 垃圾回收 (清理 60秒前的历史记录)
                        now = time.time()
                        # 注意 processed_packets 的 key 变成了 tuple，这里依然有效
                        keys_to_remove = [k for k, v in self.processed_packets.items() if now - v > 60]
                        for k in keys_to_remove: del self.processed_packets[k]

            except socket.timeout:
                continue 
            except OSError:
                if not self.running: break
            except Exception as e:
                if not self.running: break
                print(f"[RUDP] Listen Error: {e}")
                
    def punch_hole(self, target_ip, target_port):
        self.peer_addr = (target_ip, int(target_port))
        # 快速发送几个小包打通 NAT
        for _ in range(5):
            self.sock.sendto(b'PUNCH', self.peer_addr)
            time.sleep(0.1)