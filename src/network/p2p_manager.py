# src/network/p2p_manager.py

import json
import base64
import threading
import socket
import struct
import os
import random
import time
from .rudp import ReliableUDPSocket
from .secure_channel import SecureChannel

class P2PManager:
    def __init__(self):
        self.rudp = ReliableUDPSocket()
        # [核心] 维护多对等点状态
        # 结构: { (ip, port): {'channel': SecureChannel(), 'established': bool} }
        self.peers = {} 
        
        self.on_msg_callback = None
        self.my_public_info = None
        self.msg_thread_started = False
        
        # 模式标志
        self.is_server = False 
        self.server_addr = None # Client模式下记录Server地址

    def _ensure_started(self):
        """确保网络层已完全启动"""
        self.rudp.start() 
        if not self.msg_thread_started:
            self.msg_thread_started = True
            threading.Thread(target=self._message_loop, daemon=True).start()

    # ==========================================
    # 模式 1: Server Mode (聚合者)
    # ==========================================
    def start_as_server(self, port=None):
        """启动为 Server 模式，等待连接"""
        self.is_server = True
        # RUDP 在 init 时已绑定端口，这里确认启动
        self._ensure_started()
        self._resolve_public_info()
        print(f"✅ Server 启动成功，监听端口: {self.rudp.sock.getsockname()[1]}")
        print(f"   邀请码: {self.get_invitation_code()}")

    # ==========================================
    # 模式 2: Client Mode (参与者)
    # ==========================================
    def connect_via_code(self, peer_code):
        """连接对方 (Client 连接 Server)"""
        self.is_server = False
        self._ensure_started()
        try:
            info = json.loads(base64.b64decode(peer_code).decode())
            target_ip = info['ip']
            target_port = info['port']
            self.server_addr = (target_ip, int(target_port))
            
            print(f"解析邀请码成功: 目标 {target_ip}:{target_port}")
            # RUDP 打洞
            self.rudp.punch_hole(target_ip, target_port)
            
            # Client 模式下，预先初始化 Server 的通道槽位
            self._get_or_create_channel(self.server_addr)
            return True
        except Exception as e:
            print(f"连接失败: {e}")
            return False

    # ==========================================
    # 通用功能
    # ==========================================
    def get_invitation_code(self):
        """获取本机邀请码"""
        if not self.my_public_info:
            self._resolve_public_info()
        return base64.b64encode(json.dumps(self.my_public_info).encode()).decode()

    def _resolve_public_info(self):
        """执行 STUN 查询并缓存结果"""
        print("正在查询公网 IP (STUN)...")
        stun_servers = [("stun.l.google.com", 19302), ("stun1.l.google.com", 19302)]
        external_ip = None
        external_port = None
        sock = self.rudp.sock 
        orig_timeout = sock.gettimeout()
        sock.settimeout(2.0)
        
        for stun_host, stun_port in stun_servers:
            try:
                res = self._perform_stun_query(sock, stun_host, stun_port)
                if res:
                    external_ip, external_port = res
                    break
            except: continue
        
        sock.settimeout(orig_timeout)

        # Fallback 逻辑: 如果 STUN 失败，使用局域网 IP
        if not external_ip:
            print("⚠️ STUN 失败，切换到局域网模式")
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                external_ip = s.getsockname()[0]
                s.close()
            except:
                external_ip = "127.0.0.1"
        
        local_port = sock.getsockname()[1]
        # 如果 STUN 获取了映射端口则使用之，否则使用本地绑定端口
        final_port = external_port if external_ip and external_port else local_port

        self.my_public_info = {"ip": external_ip, "port": final_port}
        # print(f"✅ 网络信息: {external_ip}:{final_port}")

    def _get_or_create_channel(self, addr):
        """获取指定地址的安全通道，如果不存在则创建"""
        # 确保 addr 是 tuple (ip, port)
        if isinstance(addr, list):
            addr = tuple(addr)
            
        if addr not in self.peers:
            self.peers[addr] = {
                'channel': SecureChannel(),
                'established': False
            }
        return self.peers[addr]['channel']

    def handshake_initiate(self, target_pk, my_sk):
        """
        [Client] 发起握手
        Client 必须已经调用 connect_via_code 设置了 server_addr
        """
        if not self.server_addr:
            print("❌ 错误: 未连接任何目标")
            return

        channel = self._get_or_create_channel(self.server_addr)
        print("正在向服务器发起加密握手...")
        
        handshake_data = channel.setup_host_session_signed(target_pk, my_sk)
        msg = {
            "type": "HANDSHAKE",
            "payload": base64.b64encode(handshake_data).decode()
        }
        # 指定发送给 Server
        self.rudp.send(json.dumps(msg).encode(), self.server_addr)

    def send_secure_message(self, msg_type, data_dict, target_addr=None):
        """
        发送加密消息
        - Client 模式: 默认发给 Server (无需指定 target_addr)
        - Server 模式: 必须指定 target_addr
        """
        dest = target_addr
        if not dest:
            if not self.is_server and self.server_addr:
                dest = self.server_addr
            else:
                print("⚠️ 错误: Server 模式下发送消息必须指定目标地址")
                return False

        if dest not in self.peers:
            print(f"⚠️ 错误: 与目标 {dest} 未建立连接")
            return False

        channel = self.peers[dest]['channel']
        if not channel.is_established:
            print(f"⚠️ 错误: 与 {dest} 的安全通道未建立")
            return False
            
        inner_message = {"type": msg_type, "payload": data_dict}
        raw_inner = json.dumps(inner_message).encode()
        
        encrypted = channel.encrypt_traffic(raw_inner)
        
        packet = {
            "type": "SECURE", 
            "payload": base64.b64encode(encrypted).decode()
        }
        
        return self.rudp.send(json.dumps(packet).encode(), dest)

    def broadcast(self, msg_type, data_dict):
        """
        [Server] 广播消息给所有已连接且握手完成的 Peer
        """
        print(f"📢 正在广播消息 [{msg_type}] 给 {len(self.peers)} 个节点...")
        for addr, peer_info in self.peers.items():
            if peer_info.get('established', False):
                self.send_secure_message(msg_type, data_dict, target_addr=addr)

    def _message_loop(self):
        """处理接收到的 RUDP 消息 (修复版)"""
        print("[P2P] 消息处理线程已启动")
        while True:
            try:
                # 1. 获取消息 (阻塞)
                # 兼容新版 rudp.recv() 返回 (data, addr)
                result = self.rudp.recv() 
                
                if isinstance(result, tuple):
                    data, addr = result
                else:
                    # 旧版 rudp 兼容 (虽然不建议混用)
                    data = result
                    addr = self.server_addr 

                if not data: continue
                
                # 2. 解析 JSON
                try:
                    # 确保 data 是 bytes
                    if hasattr(data, 'decode'):
                        msg_str = data.decode()
                    else:
                        msg_str = str(data)

                    msg = json.loads(msg_str)
                    outer_type = msg.get("type")
                    payload_b64 = msg.get("payload")
                    
                    if not outer_type: continue

                    # 获取对应的通道 (自动创建以支持 Server 模式下新 Client 接入)
                    channel = self._get_or_create_channel(addr)

                    if outer_type == "HANDSHAKE":
                        print(f"[P2P] 收到握手请求 From {addr}")
                        if self.on_msg_callback:
                            raw_handshake = base64.b64decode(payload_b64)
                            # 回调给上层 (传入 addr)
                            self.on_msg_callback("HANDSHAKE", raw_handshake, addr)
                            
                    elif outer_type == "SECURE":
                        if channel.is_established:
                            encrypted = base64.b64decode(payload_b64)
                            decrypted = channel.decrypt_traffic(encrypted)
                            
                            if decrypted:
                                try:
                                    inner_msg = json.loads(decrypted.decode())
                                    real_type = inner_msg.get("type")
                                    real_payload = inner_msg.get("payload")
                                    
                                    # 标记连接已建立 (如果是第一次收到加密消息)
                                    self.peers[addr]['established'] = True
                                    
                                    if self.on_msg_callback:
                                        self.on_msg_callback(real_type, real_payload, addr)
                                        
                                except json.JSONDecodeError:
                                    print(f"⚠️ 解密成功但内部格式错误 From {addr}")
                            else:
                                print(f"⚠️ 解密失败 (Tag校验不通过) From {addr}")
                        else:
                            print(f"⚠️ 收到 SECURE 消息，但通道未建立 From {addr}")
                    
                    else:
                        print(f"⚠️ 未知消息类型: {outer_type}")

                except json.JSONDecodeError:
                    pass
            except Exception as e:
                print(f"消息循环异常: {e}")

    def _perform_stun_query(self, sock, stun_host, stun_port):
        # STUN 协议实现 (保持不变)
        msg_type = b'\x00\x01'
        msg_len = b'\x00\x00'
        magic_cookie = b'\x21\x12\xA4\x42'
        trans_id = os.urandom(12) 
        packet = msg_type + msg_len + magic_cookie + trans_id
        sock.sendto(packet, (stun_host, stun_port))
        try:
            data, addr = sock.recvfrom(2048)
            if len(data) < 20: return None
            if data[0:2] != b'\x01\x01': return None
            idx = 20
            while idx < len(data):
                attr_type = data[idx:idx+2]
                attr_len = struct.unpack("!H", data[idx+2:idx+4])[0]
                val_idx = idx + 4
                if attr_type == b'\x00\x20': 
                    port = struct.unpack("!H", data[val_idx+2:val_idx+4])[0] ^ 0x2112
                    ip_int = struct.unpack("!I", data[val_idx+4:val_idx+8])[0] ^ 0x2112A442
                    return socket.inet_ntoa(struct.pack("!I", ip_int)), port
                idx += 4 + attr_len
        except: return None
        return None