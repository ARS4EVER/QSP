"""
src/network/secure_link.py
[Phase 8] 抗量子安全信道接管与可靠传输集成层 (注入心跳防老化机制)
将 Socket、加密通道、RUDP 队列、拥塞控制与 NAT 保活融为一体的终极门面。
"""

from typing import Callable, Optional
import time
import threading

from src.network.protocol import QSPProtocol, PacketType
from src.network.secure_channel import SecureChannel, ChannelState
from src.network.rudp import RUDPConnection
from src.network.congestion import HybridCongestionControl


class SecureLink:
    def __init__(self, 
                 send_raw_fn: Callable[[bytes, tuple], None], 
                 peer_addr: tuple, 
                 session_id: int, 
                 role: str = 'client', 
                 peer_fp: str = "",          # 改为接收指纹字符串
                 local_pk: bytes = b"",      # 新增传入本地公钥
                 local_sk: bytes = b""):
        
        print(f"[SecureLink] === 初始化安全链接 ===")
        print(f"[SecureLink] 对方地址: {peer_addr}")
        print(f"[SecureLink] 会话 ID: {session_id}")
        print(f"[SecureLink] 角色: {role}")
        
        self._send_raw_external = send_raw_fn
        self.peer_addr = peer_addr
        self.session_id = session_id

        # 实例化安全通道时传入指纹和公钥
        self.sec_channel = SecureChannel(role=role, my_pk=local_pk, my_sk=local_sk, peer_fp=peer_fp)
        self.rudp = RUDPConnection(session_id)
        self.cc = HybridCongestionControl()

        self.on_handshake_done: Optional[Callable] = None
        self.on_data_received: Optional[Callable[[bytes], None]] = None

        # --- NAT 洞口防老化心跳机制 ---
        self.last_send_time = time.time()
        self.last_recv_time = time.time()
        self.is_running = True
        self.heartbeat_interval = 15.0 # 每 15 秒空闲触发一次
        
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

    def stop(self):
        """安全释放后台心跳线程"""
        self.is_running = False

    def _send_wrapped(self, data: bytes):
        """统一拦截发送操作，更新最后发送时间，压制冗余心跳"""
        self.last_send_time = time.time()
        self._send_raw_external(data, self.peer_addr)

    def _heartbeat_loop(self):
        """心跳守护线程：侦测空闲状态并发送 KEEPALIVE 刷新路由器 NAT 映射"""
        while self.is_running:
            time.sleep(1.0) # 每秒醒来检查一次
            if self.sec_channel.state != ChannelState.ESTABLISHED:
                continue
                
            now = time.time()
            # 如果距离上次发包已经超过设定间隔，就打一个心跳包出去
            if now - self.last_send_time >= self.heartbeat_interval:
                pkt = QSPProtocol.pack(
                    PacketType.KEEPALIVE, 
                    seq=0, 
                    payload=b"PING", 
                    session_id=self.session_id
                )
                self._send_wrapped(pkt)

    def initiate_security_handshake(self):
        print(f"[SecureLink] 发起安全握手...")
        if self.sec_channel.role != 'client':
            return
        
        init_payload = self.sec_channel.initiate_handshake()
        pkt = QSPProtocol.pack(
            PacketType.HANDSHAKE_INIT, 
            seq=0, 
            payload=init_payload, 
            session_id=self.session_id
        )
        print(f"[SecureLink] 发送握手初始化包，长度: {len(pkt)} 字节")
        self._send_wrapped(pkt)

    def handle_network_packet(self, parsed_pkt: dict):
        # 只要收到来自该通道的任何包，都更新接收时间
        self.last_recv_time = time.time()
        
        msg_type = parsed_pkt['type']
        
        # 如果是心跳包，已经更新了时间戳，直接丢弃即可，不需要交由上层处理
        if msg_type == PacketType.KEEPALIVE:
            return

        payload = parsed_pkt['payload']
        seq = parsed_pkt['seq']
        ack = parsed_pkt['ack']

        if msg_type == PacketType.HANDSHAKE_INIT:
            print(f"[SecureLink] 收到握手初始化包")
            resp_payload = self.sec_channel.handle_handshake_request(payload)
            pkt = QSPProtocol.pack(
                PacketType.HANDSHAKE_RESP, 
                seq=0, 
                payload=resp_payload, 
                session_id=self.session_id
            )
            print(f"[SecureLink] 发送握手响应包，长度: {len(pkt)} 字节")
            self._send_wrapped(pkt)
            if self.sec_channel.state == ChannelState.ESTABLISHED:
                print(f"[SecureLink] ✓ 服务端安全握手完成")
                if self.on_handshake_done:
                    self.on_handshake_done()

        elif msg_type == PacketType.HANDSHAKE_RESP:
            print(f"[SecureLink] 收到握手响应包")
            self.sec_channel.handle_handshake_response(payload)
            if self.sec_channel.state == ChannelState.ESTABLISHED:
                print(f"[SecureLink] ✓ 客户端安全握手完成")
                if self.on_handshake_done:
                    self.on_handshake_done()

        elif msg_type == PacketType.DATA:
            if self.sec_channel.state != ChannelState.ESTABLISHED:
                return

            cleartext = self.sec_channel.decrypt_payload(payload)
            deliverable, current_ack, sack_blocks = self.rudp.receive_data(seq, cleartext)
            sack_payload = QSPProtocol.build_sack_payload(sack_blocks)
            
            ack_pkt = QSPProtocol.pack(
                PacketType.SACK, 
                seq=0, 
                payload=sack_payload, 
                ack=current_ack, 
                session_id=self.session_id
            )
            self._send_wrapped(ack_pkt)

            if self.on_data_received:
                for data in deliverable:
                    self.on_data_received(data)

        elif msg_type == PacketType.SACK:
            sack_blocks = QSPProtocol.parse_sack_blocks(payload)
            retransmits, rtt_sample = self.rudp.handle_sack(ack, sack_blocks)

            if len(retransmits) > 0:
                self.cc.on_loss()
            elif rtt_sample > 0:
                self.cc.on_ack(rtt=rtt_sample)

            for r_seq, encrypted_payload in retransmits:
                pkt = QSPProtocol.pack(
                    PacketType.DATA, 
                    seq=r_seq, 
                    payload=encrypted_payload, 
                    session_id=self.session_id
                )
                self._send_wrapped(pkt)

    def send_reliable(self, cleartext: bytes):
        if self.sec_channel.state != ChannelState.ESTABLISHED:
            raise PermissionError("安全信道尚未建立，拒绝传输资产数据。")

        encrypted_payload = self.sec_channel.encrypt_payload(cleartext)
        seq = self.rudp.next_seq_num
        self.rudp.track_sent_packet(seq, encrypted_payload)
        
        pkt = QSPProtocol.pack(
            PacketType.DATA, 
            seq=seq, 
            payload=encrypted_payload, 
            session_id=self.session_id
        )
        self._send_wrapped(pkt)
