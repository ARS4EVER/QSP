"""
src/network/p2p_manager.py
[Phase 5 Refactor] 多路并发 P2P 节点管理器
"""

import socket
import struct
import json
import base64
import zlib
import hashlib
import threading
import time
import traceback
import logging
from typing import Callable, Optional, Dict, Tuple
from enum import Enum

logger = logging.getLogger('QSP.P2P')

_ignore_count = 0

from .protocol import QSPProtocol, PacketType
from .secure_link import SecureLink
from src.app.app_router import AppRouter
from src.app.app_protocol import AppMessage, AppMessageV2


class PunchState(Enum):
    IDLE = 0
    PUNCHING = 1
    CONNECTED = 2
    FAILED = 3


class STUNClient:
    STUN_SERVERS = [
        ('stun.qq.com', 3478),           
        ('stun.miwifi.com', 3478),       
        ('stun.aliyun.com', 3478),       
        ('stun.l.google.com', 19302),    
        ('stun.ekiga.net', 3478),
    ]
    
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.local_ip = self._get_local_ip()
        self.public_ip, self.public_port = None, None
    
    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def discover_public_coordinates(self):
        import os
        magic_cookie = 0x2112A442
        transaction_id = os.urandom(12)
        req = struct.pack('!H', 0x0001) + struct.pack('!H', 0x0000) + struct.pack('!I', magic_cookie) + transaction_id
        
        for stun_server in self.STUN_SERVERS:
            try:
                self.sock.sendto(req, stun_server)
                data, _ = self.sock.recvfrom(2048)
                if len(data) >= 20 and struct.unpack('!HH', data[:4])[0] == 0x0101:
                    pos = 20
                    while pos + 4 <= len(data):
                        attr_type, attr_len = struct.unpack('!HH', data[pos:pos+4])
                        if attr_type in (0x0001, 0x0020) and attr_len >= 8:
                            if struct.unpack('!B', data[pos+5:pos+6])[0] == 0x01:
                                port = struct.unpack('!H', data[pos+6:pos+8])[0]
                                ip_bytes = data[pos+8:pos+12]
                                if attr_type == 0x0020:
                                    port ^= (magic_cookie >> 16)
                                    ip_bytes = struct.pack('!I', struct.unpack('!I', ip_bytes)[0] ^ magic_cookie)
                                self.public_ip = socket.inet_ntoa(ip_bytes)
                                self.public_port = port
                                return True
                        pos += 4 + attr_len
            except Exception:
                continue
        return False


class InviteCodeManager:
    @staticmethod
    def generate_invite_code(local_ip, local_port, public_ip, public_port, dil_pk):
        fp = hashlib.sha256(dil_pk).hexdigest()[:16] if dil_pk else ""
        data = {"lip": local_ip, "lport": local_port, "pip": public_ip, "pport": public_port, "fp": fp}
        compressed = zlib.compress(json.dumps(data).encode('utf-8'))
        return f"QSP-Invite://{base64.b64encode(compressed).decode('utf-8')}"
    
    @staticmethod
    def parse_invite_code(code_str):
        if not code_str.startswith("QSP-Invite://"): raise ValueError("Invalid invite code format")
        b64_str = code_str[len("QSP-Invite://"):]
        return json.loads(zlib.decompress(base64.b64decode(b64_str)).decode('utf-8'))


class P2PNode:
    def __init__(self, host='0.0.0.0', port=9999, static_sk=None, dil_pk=b""):
        self.host = host
        self.port = port
        self.running = False
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        
        self.sock.settimeout(1.0)
        
        if self.port == 0:
            self.port = self.sock.getsockname()[1]
            
        self.static_sk = static_sk
        self.dil_pk = dil_pk
        
        self.node_id = hashlib.sha256(dil_pk).hexdigest()[:16] if dil_pk else ""
        
        self.stun_client = STUNClient(self.sock)
        self.local_ip = self.stun_client.local_ip
        self.public_ip, self.public_port = None, None
        
        self.punch_state = PunchState.IDLE
        self.peer_addr = None
        self.session_id = 0
        self.on_physically_connected: Optional[Callable] = None

        self.secure_links: Dict[Tuple[str, int], SecureLink] = {}

        self.connected_peers: Dict[str, Tuple[str, int]] = {}
        
        self.router = AppRouter()
        
        self.ui_callback = None
        
        self._lock = threading.Lock()
    
    @property
    def secure_link(self):
        if self.secure_links:
            return list(self.secure_links.values())[0]
        return None

    def discover_public_coordinates(self):
        print(f"[P2P] 正在发现公网坐标...")
        if self.stun_client.discover_public_coordinates():
            self.public_ip, self.public_port = self.stun_client.public_ip, self.stun_client.public_port
            print(f"[P2P] ✓ 公网坐标发现成功: {self.public_ip}:{self.public_port}")
            return True
        print(f"[P2P] ✗ 公网坐标发现失败，使用本地坐标")
        return False
    
    def generate_invite_code(self):
        pip, pport = self.public_ip or self.local_ip, self.public_port or self.port
        fp = hashlib.sha256(self.dil_pk).hexdigest()[:16] if self.dil_pk else ""
        print(f"[P2P] 生成邀请码，使用坐标: 本地={self.local_ip}:{self.port}, 公网={pip}:{pport}")
        print(f"[P2P] 本节点公钥指纹: {fp}")
        return InviteCodeManager.generate_invite_code(self.local_ip, self.port, pip, pport, self.dil_pk)

    def start(self):
        self.running = True
        threading.Thread(target=self._listen_loop, daemon=True).start()
        print(f"[P2P] ✓ 节点已启动在 {self.host}:{self.port}")

    def stop(self):
        self.running = False
        
        for link in self.secure_links.values():
            if hasattr(link, 'stop'):
                link.stop()
                
        try:
            self.sock.close()
        except Exception: pass

    def connect_via_invite(self, target_invite_code: str, session_id: int):
        print(f"[P2P] === 开始连接 ===")
        print(f"[P2P] 解析邀请码...")
        target_info = InviteCodeManager.parse_invite_code(target_invite_code)
        print(f"[P2P] ✓ 邀请码解析成功: {target_info}")
        self.session_id = session_id
        self.punch_state = PunchState.PUNCHING

        self.target_peer_fp = target_info.get('fp', "")
        print(f"[P2P] 对方公钥指纹: {self.target_peer_fp}")
        
        public_addr = (target_info['pip'], target_info['pport'])
        local_addr = (target_info['lip'], target_info['lport'])
        
        threading.Thread(target=self._holepunch_worker, args=(public_addr, local_addr), daemon=True).start()

    def _holepunch_worker(self, public_addr: tuple, local_addr: tuple):
        print(f"[P2P] === 开始 UDP 打洞 ===")
        print(f"[P2P] 目标公网地址: {public_addr}")
        print(f"[P2P] 目标本地地址: {local_addr}")
        print(f"[P2P] 会话 ID: {self.session_id}")
        
        pkt = QSPProtocol.pack(PacketType.HOLEPUNCH, seq=0, payload=b"PUNCH", session_id=self.session_id)
        attempts = 0
        while self.punch_state == PunchState.PUNCHING and attempts < 50:
            try:
                sent_to = []
                if public_addr[0] and public_addr[1]:
                    self._send_raw(pkt, public_addr)
                    sent_to.append(f"公网 {public_addr}")
                if local_addr != public_addr and local_addr[0] and local_addr[1]:
                    self._send_raw(pkt, local_addr)
                    sent_to.append(f"本地 {local_addr}")
                
                if attempts % 10 == 0:
                    print(f"[P2P] 打洞尝试 #{attempts}/50, 发送到: {', '.join(sent_to)}")
            except Exception as e:
                print(f"[P2P] 发送错误 (尝试 #{attempts}): {e}")
            time.sleep(0.2)
            attempts += 1
            
        if self.punch_state == PunchState.PUNCHING:
            self.punch_state = PunchState.FAILED
            print("[P2P] ❌ UDP 打洞超时")
            print("[P2P] 可能原因:")
            print("[P2P]   1. 对方节点不在线")
            print("[P2P]   2. NAT 类型不兼容")
            print("[P2P]   3. 防火墙阻止 UDP 流量")
            print("[P2P]   4. 同一网络下请尝试使用本地 IP")
        elif self.punch_state == PunchState.CONNECTED:
            print(f"[P2P] ✓ UDP 打洞成功! 已连接到 {self.peer_addr}")

    def _send_raw(self, data: bytes, addr: tuple):
        try:
            self.sock.sendto(data, addr)
        except Exception as e:
            print(f"[P2P] 发送到 {addr} 失败: {e}")

    def _listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                if not data: continue
                self._handle_packet(data, addr)
            except socket.timeout:
                pass
            except OSError:
                pass
            except Exception as e:
                if self.running: 
                    print(f"[P2P] 监听错误: {e}")
                    traceback.print_exc()

    def _handle_packet(self, data: bytes, addr: tuple):
        try:
            parsed = QSPProtocol.unpack(data)
            msg_type = parsed['type']
            session_id = parsed.get('session_id', 0)
            
            if msg_type == PacketType.HOLEPUNCH:
                print(f"[P2P] 收到来自 {addr} 的打洞包 (会话 ID: {session_id})")
                ack_pkt = QSPProtocol.pack(PacketType.HOLEPUNCH_ACK, seq=0, payload=b"ACK", session_id=session_id)
                self._send_raw(ack_pkt, addr)
                print(f"[P2P] 已发送打洞确认到 {addr}")
                if addr not in self.secure_links:
                    print(f"[P2P] 创建服务端安全链接到 {addr}")
                    self._mark_connected(addr, session_id, role='server')
                    
            elif msg_type == PacketType.HOLEPUNCH_ACK:
                print(f"[P2P] 收到来自 {addr} 的打洞确认 (会话 ID: {session_id})")
                if self.punch_state == PunchState.PUNCHING and addr not in self.secure_links:
                    print(f"[P2P] 创建客户端安全链接到 {addr}")
                    self._mark_connected(addr, session_id, role='client')
                    
            elif msg_type in (PacketType.HANDSHAKE_INIT, PacketType.HANDSHAKE_RESP, PacketType.DATA, PacketType.SACK, PacketType.KEEPALIVE):
                if addr in self.secure_links:
                    self.secure_links[addr].handle_network_packet(parsed)
                elif msg_type == PacketType.HANDSHAKE_INIT:
                    print(f"[P2P] 收到来自 {addr} 的握手初始化包")
                    self._mark_connected(addr, session_id, role='server')
                    self.secure_links[addr].handle_network_packet(parsed)
                elif msg_type == PacketType.HANDSHAKE_RESP:
                    pass
                    
        except ValueError as e:
            error_msg = str(e)
            global _ignore_count
            
            if "Invalid magic number" in error_msg:
                _ignore_count += 1
                if _ignore_count <= 5:
                    logger.debug(f"[P2P] 忽略非QSP数据包 (来源: {addr}, 魔数: {error_msg.split(': ')[-1]})")
                elif _ignore_count == 6:
                    logger.info("[P2P] 网络噪声过滤已启用，后续此类消息将被静默")
            elif "Unsupported protocol version" in error_msg:
                logger.warning(f"[P2P] 收到不同协议版本的数据包: {error_msg}")
            else:
                logger.warning(f"[P2P] 解析包错误: {error_msg}")
                _ignore_count = 0

    def _mark_connected(self, addr: tuple, session_id: int, role: str):
        print(f"[P2P] === 标记连接 ===")
        print(f"[P2P] 地址: {addr}")
        print(f"[P2P] 角色: {role}")
        print(f"[P2P] 会话 ID: {session_id}")
        
        self.punch_state = PunchState.CONNECTED
        self.peer_addr = addr
        
        if addr not in self.secure_links:
            peer_fp = getattr(self, 'target_peer_fp', "") if role == 'client' else ""
            print(f"[P2P] 使用对方指纹: {peer_fp if peer_fp else '(无)'}")
            
            link = SecureLink(
                send_raw_fn=self._send_raw,
                peer_addr=addr,
                session_id=session_id,
                role=role,
                peer_fp=peer_fp,
                local_pk=self.dil_pk,
                local_sk=self.static_sk
            )
            self.secure_links[addr] = link
            print(f"[P2P] ✓ 安全链接已创建")
            
            if self.on_physically_connected:
                self.on_physically_connected(addr)
                
            if role == 'client':
                print(f"[P2P] 客户端发起安全握手...")
                link.initiate_security_handshake()
                
                if hasattr(link, 'on_link_established'):
                    link.on_link_established = self._on_link_established
                if hasattr(link, 'on_app_data_received'):
                    link.on_app_data_received = self._on_app_data_received
                if hasattr(link, 'on_link_closed'):
                    link.on_link_closed = self._on_link_closed

    def set_ui_callback(self, cb):
        self.ui_callback = cb


    def _on_link_established(self, peer_addr: tuple, verified_node_id: str):
        with self._lock:
            self.connected_peers[verified_node_id] = peer_addr
            
        logging.info(f"[P2PNode] 节点 {verified_node_id} (@{peer_addr}) 已完成双向认证，正式加入安全路由表。")
        
        if self.ui_callback:
            self.ui_callback('peer_connected', verified_node_id)

    def _on_app_data_received(self, verified_node_id: str, plaintext: bytes):
        self.router.route_message(verified_node_id, plaintext)

    def _on_link_closed(self, peer_addr: tuple, verified_node_id: str):
        with self._lock:
            if peer_addr in self.secure_links:
                del self.secure_links[peer_addr]
            if verified_node_id and verified_node_id in self.connected_peers:
                del self.connected_peers[verified_node_id]
                
        logging.info(f"[P2PNode] 与节点 {verified_node_id} 的连接已安全清理。")
        
        if self.ui_callback and verified_node_id:
            self.ui_callback('peer_disconnected', verified_node_id)

    
    def send_message(self, target_node_id: str, msg: AppMessage):
        with self._lock:
            if target_node_id not in self.connected_peers:
                logging.error(f"[P2PNode] 拒绝发送：节点 {target_node_id} 不在安全路由表中 (未连接或未认证)。")
                return
                
            peer_addr = self.connected_peers[target_node_id]
            link = self.secure_links.get(peer_addr)
        
        if link:
            if isinstance(msg, AppMessageV2):
                msg = AppMessageV2(
                    cmd=msg.cmd,
                    sender_id=self.node_id,
                    payload=msg.payload
                )
            else:
                msg.sender_id = self.node_id
            if hasattr(link, 'send_app_data'):
                link.send_app_data(msg.encode())
            elif hasattr(link, 'send_reliable'):
                link.send_reliable(msg.encode())
