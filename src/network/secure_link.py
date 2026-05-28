import logging
import time
import threading
from typing import Callable, Optional

from src.network.secure_channel import SecureChannel, ChannelState


class SecureLink:
    """
    QSP 安全链路管理器
    
    作为底层物理网络 (UDP/RUDP) 和加密信道 (SecureChannel) 之间的桥梁:
    - 管理安全信道生命周期
    - 集成 RUDP 可靠传输
    - 集成拥塞控制
    - 心跳保活机制
    """

    def __init__(self, *args, **kwargs):
        if len(args) >= 1 and isinstance(args[0], bool):
            self._init_new_api(*args, **kwargs)
        else:
            self._init_old_api(*args, **kwargs)
    
    def _init_new_api(self, is_server: bool, peer_addr: tuple, my_keypair: dict, expected_fp: str = None):
        """初始化新 API 格式"""
        self.peer_addr = peer_addr
        self.channel = SecureChannel(is_server=is_server, my_identity_keypair=my_keypair, expected_peer_fp=expected_fp)
        self._was_established = False
        
        self._handshake_timer = None
        self.handshake_timeout_sec = 5.0 
        
        self.send_raw_network_func = None  
        self.on_link_established = None   
        self.on_app_data_received = None  
        self.on_link_closed = None      

        self.channel.set_send_callback(self._raw_send)
    
    def _init_old_api(self, send_raw_fn, peer_addr, session_id, role='client', peer_fp="", local_pk=b"", local_sk=b""):
        """初始化旧 API 格式"""
        self._send_raw_external = send_raw_fn
        self.peer_addr = peer_addr
        self.session_id = session_id
        self.role = role

        self.sec_channel = SecureChannel(role=role, my_pk=local_pk, my_sk=local_sk, peer_fp=peer_fp)
        self.channel = self.sec_channel 

        self._was_established = False

        self.on_handshake_done = None
        self.on_data_received = None

        self.on_link_established = None
        self.on_app_data_received = None
        self.on_link_closed = None

        self.last_send_time = time.time()
        self.last_recv_time = time.time()
        self.is_running = True
        self.heartbeat_interval = 15.0
        
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
    
    def get_session_key(self) -> Optional[bytes]:
        """获取当前会话的共享密钥，用于清单加密"""
        if hasattr(self, 'channel') and self.channel.state == ChannelState.ESTABLISHED:
            return self.channel.session_key
        return None

    def stop(self):
        """停止安全链路"""
        if hasattr(self, 'is_running'):
            self.is_running = False
    
    def _heartbeat_loop(self):
        """心跳保活循环"""
        while self.is_running:
            time.sleep(1.0)
            if self.sec_channel.state != ChannelState.ESTABLISHED:
                continue
                
            now = time.time()
            if now - self.last_send_time >= self.heartbeat_interval:
                from src.network.protocol import QSPProtocol, PacketType
                pkt = QSPProtocol.pack(
                    PacketType.KEEPALIVE, 
                    seq=0, 
                    payload=b"PING", 
                    session_id=self.session_id
                )
                self._send_wrapped(pkt)
    
    def _send_wrapped(self, data: bytes):
        """发送数据包装"""
        self.last_send_time = time.time()
        self._send_raw_external(data, self.peer_addr)
    
    def initiate_security_handshake(self):
        """发起安全握手"""
        if self.sec_channel.role != 'client':
            return
        
        init_payload = self.sec_channel.initiate_handshake()
        from src.network.protocol import QSPProtocol, PacketType
        pkt = QSPProtocol.pack(
            PacketType.HANDSHAKE_INIT, 
            seq=0, 
            payload=init_payload, 
            session_id=self.session_id
        )
        self._send_wrapped(pkt)
    
    def handle_network_packet(self, parsed_pkt: dict):
        """处理网络数据包"""
        self.last_recv_time = time.time()
        
        from src.network.protocol import PacketType
        
        msg_type = parsed_pkt['type']
        
        if msg_type == PacketType.KEEPALIVE:
            return

        payload = parsed_pkt['payload']
        seq = parsed_pkt['seq']
        ack = parsed_pkt['ack']

        if msg_type == PacketType.HANDSHAKE_INIT:
            resp_payload = self.sec_channel.handle_handshake_request(payload)
            from src.network.protocol import QSPProtocol
            pkt = QSPProtocol.pack(
                PacketType.HANDSHAKE_RESP, 
                seq=0, 
                payload=resp_payload, 
                session_id=self.session_id
            )
            self._send_wrapped(pkt)
            if self.sec_channel.state == ChannelState.ESTABLISHED:
                if self.on_handshake_done:
                    self.on_handshake_done()

        elif msg_type == PacketType.HANDSHAKE_RESP:
            self.sec_channel.handle_handshake_response(payload)
            if self.sec_channel.state == ChannelState.ESTABLISHED:
                if self.on_handshake_done:
                    self.on_handshake_done()

        elif msg_type == PacketType.DATA:
            if self.sec_channel.state != ChannelState.ESTABLISHED:
                return

            from src.network.rudp import RUDPConnection
            from src.network.protocol import QSPProtocol
            
            cleartext = self.sec_channel.decrypt_payload(payload)
            self.rudp = RUDPConnection(self.session_id) if not hasattr(self, 'rudp') else self.rudp
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

            if self.on_app_data_received:
                for data in deliverable:
                    self.on_app_data_received(str(self.peer_addr), data)
            elif self.on_data_received:
                for data in deliverable:
                    self.on_data_received(data)

        elif msg_type == PacketType.SACK:
            from src.network.protocol import QSPProtocol
            from src.network.congestion import HybridCongestionControl
            
            sack_blocks = QSPProtocol.parse_sack_blocks(payload)
            retransmits, rtt_sample = self.rudp.handle_sack(ack, sack_blocks)
            
            self.cc = HybridCongestionControl() if not hasattr(self, 'cc') else self.cc

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
        """可靠发送数据"""
        if self.sec_channel.state != ChannelState.ESTABLISHED:
            raise PermissionError("安全信道尚未建立，拒绝传输资产数据。")

        encrypted_payload = self.sec_channel.encrypt_payload(cleartext)
        
        from src.network.rudp import RUDPConnection
        from src.network.protocol import QSPProtocol, PacketType
        
        self.rudp = RUDPConnection(self.session_id) if not hasattr(self, 'rudp') else self.rudp
        seq = self.rudp.next_seq_num
        self.rudp.track_sent_packet(seq, encrypted_payload)
        
        pkt = QSPProtocol.pack(
            PacketType.DATA, 
            seq=seq, 
            payload=encrypted_payload, 
            session_id=self.session_id
        )
        self._send_wrapped(pkt)

    def receive_network_data(self, data: bytes):
        """接收网络数据"""
        try:
            prev_state = self.channel.state
            
            self.channel.feed_data(data)
            
            self._check_state_transition(prev_state)
            
        except Exception as e:
            logging.error(f"[SecureLink] 处理物理层数据时发生严重异常: {e}")
            self.close()

    def _check_state_transition(self, prev_state: ChannelState):
        """检查并处理状态转换"""
        if self.channel.state == ChannelState.CLOSED:
            self.close()
            return

        current_state = self.channel.state

        if prev_state != ChannelState.WAIT_CLIENT_FINISHED and current_state == ChannelState.WAIT_CLIENT_FINISHED:
            self._start_handshake_timer()

        if not self._was_established and current_state == ChannelState.ESTABLISHED:
            self._cancel_handshake_timer()
            self._was_established = True
            
            real_remote_id = self.channel.remote_node_id
            logging.info(f"[SecureLink] 隔离墙解除！与物理坐标 {self.peer_addr} 的双向认证成功。真实身份: {real_remote_id}")

            self.channel.app_data_callback = self._handle_decrypted_app_data
            
            if self.on_link_established:
                self.on_link_established(self.peer_addr, real_remote_id)

    def _start_handshake_timer(self):
        """启动握手超时定时器"""
        self._cancel_handshake_timer()
        self._handshake_timer = threading.Timer(self.handshake_timeout_sec, self._on_handshake_timeout)
        self._handshake_timer.start()
        logging.debug(f"[Security] 启动半连接监控 ({self.peer_addr})，限时 {self.handshake_timeout_sec}s。")

    def _on_handshake_timeout(self):
        """握手超时处理"""
        if self.channel.state != ChannelState.ESTABLISHED:
            logging.warning(
                f"[Security-Firewall] 握手超时！节点 {self.peer_addr} "
                f"未能在限时内提交合法的 ClientFinished 身份证明，疑似 DoS 攻击。强制熔断！"
            )
            self.close()

    def _cancel_handshake_timer(self):
        """取消握手超时定时器"""
        if self._handshake_timer:
            self._handshake_timer.cancel()
            self._handshake_timer = None

    def _handle_decrypted_app_data(self, remote_node_id: str, plaintext: bytes):
        """处理解密后的应用数据"""
        if self.on_app_data_received:
            self.on_app_data_received(remote_node_id, plaintext)

    def send_app_data(self, plaintext: bytes):
        """发送应用数据"""
        if self.channel.state != ChannelState.ESTABLISHED:
            logging.warning(f"[SecureLink] 拦截！信道 {self.peer_addr} 尚未完成双向认证，拒绝发送应用层数据。")
            return
            
        self.channel.encrypt_and_send(plaintext)

    def _raw_send(self, data: bytes):
        """底层发送函数"""
        if self.send_raw_network_func:
            self.send_raw_network_func(self.peer_addr, data)

    def close(self):
        """关闭安全链路"""
        self._cancel_handshake_timer()
        
        if self.channel.state != ChannelState.CLOSED:
            self.channel.close()
            
        if self._was_established:
            logging.info(f"[SecureLink] 与 {self.peer_addr} 的安全链路已断开。")
            self._was_established = False

        if self.on_link_closed:
            self.on_link_closed(self.peer_addr, self.channel.remote_node_id)


class LegacySecureLink:
    """
    兼容旧版 API 的安全链路
    """
    
    def __init__(self, 
                 send_raw_fn: Callable[[bytes, tuple], None], 
                 peer_addr: tuple, 
                 session_id: int, 
                 role: str = 'client', 
                 peer_fp: str = "",          
                 local_pk: bytes = b"",      
                 local_sk: bytes = b""):
        
        self._send_raw_external = send_raw_fn
        self.peer_addr = peer_addr
        self.session_id = session_id

        my_keypair = {"pk": local_pk, "sk": local_sk}
        self.sec_channel = SecureChannel(role=role, my_pk=local_pk, my_sk=local_sk, peer_fp=peer_fp)
        
        self.on_handshake_done: Optional[Callable] = None
        self.on_data_received: Optional[Callable[[bytes], None]] = None

        self.last_send_time = time.time()
        self.last_recv_time = time.time()
        self.is_running = True
        self.heartbeat_interval = 15.0
        
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

    def stop(self):
        """停止安全链路"""
        self.is_running = False

    def _send_wrapped(self, data: bytes):
        """发送数据包装"""
        self.last_send_time = time.time()
        self._send_raw_external(data, self.peer_addr)

    def _heartbeat_loop(self):
        """心跳保活循环"""
        while self.is_running:
            time.sleep(1.0)
            if self.sec_channel.state != ChannelState.ESTABLISHED:
                continue
                
            now = time.time()
            if now - self.last_send_time >= self.heartbeat_interval:
                from src.network.protocol import QSPProtocol, PacketType
                pkt = QSPProtocol.pack(
                    PacketType.KEEPALIVE, 
                    seq=0, 
                    payload=b"PING", 
                    session_id=self.session_id
                )
                self._send_wrapped(pkt)

    def initiate_security_handshake(self):
        """发起安全握手"""
        if self.sec_channel.role != 'client':
            return
        
        init_payload = self.sec_channel.initiate_handshake()
        from src.network.protocol import QSPProtocol, PacketType
        pkt = QSPProtocol.pack(
            PacketType.HANDSHAKE_INIT, 
            seq=0, 
            payload=init_payload, 
            session_id=self.session_id
        )
        self._send_wrapped(pkt)

    def handle_network_packet(self, parsed_pkt: dict):
        """处理网络数据包"""
        self.last_recv_time = time.time()
        
        from src.network.protocol import PacketType
        
        msg_type = parsed_pkt['type']
        
        if msg_type == PacketType.KEEPALIVE:
            return

        payload = parsed_pkt['payload']
        seq = parsed_pkt['seq']
        ack = parsed_pkt['ack']

        if msg_type == PacketType.HANDSHAKE_INIT:
            resp_payload = self.sec_channel.handle_handshake_request(payload)
            from src.network.protocol import QSPProtocol
            pkt = QSPProtocol.pack(
                PacketType.HANDSHAKE_RESP, 
                seq=0, 
                payload=resp_payload, 
                session_id=self.session_id
            )
            self._send_wrapped(pkt)
            if self.sec_channel.state == ChannelState.ESTABLISHED:
                if self.on_handshake_done:
                    self.on_handshake_done()

        elif msg_type == PacketType.HANDSHAKE_RESP:
            self.sec_channel.handle_handshake_response(payload)
            if self.sec_channel.state == ChannelState.ESTABLISHED:
                if self.on_handshake_done:
                    self.on_handshake_done()

        elif msg_type == PacketType.DATA:
            if self.sec_channel.state != ChannelState.ESTABLISHED:
                return

            from src.network.rudp import RUDPConnection
            from src.network.protocol import QSPProtocol
            
            cleartext = self.sec_channel.decrypt_payload(payload)
            self.rudp = RUDPConnection(self.session_id) if not hasattr(self, 'rudp') else self.rudp
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
            from src.network.protocol import QSPProtocol
            from src.network.congestion import HybridCongestionControl
            
            sack_blocks = QSPProtocol.parse_sack_blocks(payload)
            retransmits, rtt_sample = self.rudp.handle_sack(ack, sack_blocks)
            
            self.cc = HybridCongestionControl() if not hasattr(self, 'cc') else self.cc

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
        """可靠发送数据"""
        if self.sec_channel.state != ChannelState.ESTABLISHED:
            raise PermissionError("安全信道尚未建立，拒绝传输资产数据。")

        encrypted_payload = self.sec_channel.encrypt_payload(cleartext)
        
        from src.network.rudp import RUDPConnection
        from src.network.protocol import QSPProtocol
        
        self.rudp = RUDPConnection(self.session_id) if not hasattr(self, 'rudp') else self.rudp
        seq = self.rudp.next_seq_num
        self.rudp.track_sent_packet(seq, encrypted_payload)
        
        pkt = QSPProtocol.pack(
            PacketType.DATA, 
            seq=seq, 
            payload=encrypted_payload, 
            session_id=self.session_id
        )
        self._send_wrapped(pkt)
