import json
import time
import base64
import threading
import numpy as np
from enum import Enum

# 保持原有导入
from src.network.p2p_manager import P2PManager
from src.network.protocol import ProtocolTypes
from src.crypto_lattice.signer import ThresholdSigner, SignatureAggregator
from src.secret_sharing.reconstructor import ImageCRTReconstructor
from src.image_stego.orchestrator import Module3Orchestrator
from src.crypto_lattice.encryptor import LatticeEncryptor

# === [适配器] 解决 Phase 2 与 Phase 3 密钥结构不兼容问题 ===
def adapt_crypto_key(k):
    """
    密钥结构适配器
    Phase 3 的 KeyGenerator 生成: {'rho': ..., 's1': ...}
    Phase 2 的 Encryptor 期望:   {'public_seed': ..., 's': ...}
    此函数在不修改底层代码的前提下实现兼容。
    """
    if not isinstance(k, dict): return k
    
    # 1. 适配种子: rho -> public_seed
    if 'rho' in k and 'public_seed' not in k:
        k['public_seed'] = k['rho']
        
    # 2. 适配私钥向量: s1 -> s
    if 's1' in k and 's' not in k:
        k['s'] = k['s1']
        
    return k

# === [扩展] LanP2PManager (保持之前的修复) ===
class LanP2PManager(P2PManager):
    """
    集成 LAN 模式和主动握手能力的扩展管理器
    """
    def _resolve_public_info(self):
        local_port = self.rudp.sock.getsockname()[1]
        print(f"🔵 [LanP2PManager] 局域网模式: 强制绑定 127.0.0.1:{local_port}")
        self.my_public_info = {"ip": "127.0.0.1", "port": local_port}

    def send_handshake_to_peer(self, target_addr, target_pk, my_sk):
        """Server 端主动握手"""
        try:
            channel = self._get_or_create_channel(target_addr)
            
            # [关键] 确保密钥已适配
            target_pk = adapt_crypto_key(target_pk)
            my_sk = adapt_crypto_key(my_sk)
            
            # 生成握手包 (底层会调用 encryptor)
            handshake_data = channel.setup_host_session_signed(target_pk, my_sk)
            
            msg = {
                "type": "HANDSHAKE",
                "payload": base64.b64encode(handshake_data).decode()
            }
            self.rudp.send(json.dumps(msg).encode(), target_addr)
            print(f"[LanP2P] 已向 {target_addr} 发送握手请求")
            return True
        except Exception as e:
            print(f"[LanP2P] 握手发送失败: {e}")
            # import traceback; traceback.print_exc()
            return False

    def _message_loop(self):
        """重写消息循环以支持 HELLO 透传"""
        print("[LanP2P] 增强型消息线程已启动 (支持 HELLO)")
        while True:
            try:
                result = self.rudp.recv()
                if isinstance(result, tuple):
                    data, addr = result
                else:
                    data = result
                    addr = self.server_addr

                if not data: continue

                try:
                    msg_str = data.decode() if hasattr(data, 'decode') else str(data)
                    msg = json.loads(msg_str)
                    outer_type = msg.get("type")
                    payload = msg.get("payload")

                    if not outer_type: continue

                    channel = self._get_or_create_channel(addr)

                    if outer_type == "HELLO":
                        if self.on_msg_callback:
                            self.on_msg_callback(outer_type, payload, addr)

                    elif outer_type == "HANDSHAKE":
                        if self.on_msg_callback:
                            raw_handshake = base64.b64decode(payload)
                            self.on_msg_callback("HANDSHAKE", raw_handshake, addr)

                    elif outer_type == "SECURE":
                        if channel.is_established:
                            encrypted = base64.b64decode(payload)
                            decrypted = channel.decrypt_traffic(encrypted)
                            if decrypted:
                                try:
                                    inner_msg = json.loads(decrypted.decode())
                                    real_type = inner_msg.get("type")
                                    real_payload = inner_msg.get("payload")
                                    self.peers[addr]['established'] = True
                                    if self.on_msg_callback:
                                        self.on_msg_callback(real_type, real_payload, addr)
                                except: pass
                except json.JSONDecodeError: pass
            except Exception as e:
                print(f"消息循环异常: {e}")

class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer): return int(obj)
        elif isinstance(obj, np.floating): return float(obj)
        elif isinstance(obj, np.ndarray): return obj.tolist()
        elif isinstance(obj, bytes): return obj.hex()
        return super(NumpyEncoder, self).default(obj)

class SessionState(Enum):
    IDLE = 0
    WAITING_COMMITMENTS = 1
    WAITING_RESPONSES = 2
    RECONSTRUCTING = 3
    FINISHED = 4


# === Host 逻辑 ===
class RecoveryHostSession:
    def __init__(self, my_sk, my_pk, lan_mode=False):
        self.managers = [] 
        self.peers_data = {} 
        
        # [关键适配 1] 本地密钥适配
        self.my_sk = adapt_crypto_key(my_sk)
        self.my_pk = adapt_crypto_key(my_pk)
        
        self.state = SessionState.IDLE
        self.lock = threading.Lock()
        self.lan_mode = lan_mode
        
        self.aggregator = SignatureAggregator()
        self.reconstructor = ImageCRTReconstructor()
        
        self.target_file_hash = None
        self.target_manifest = None 
        
        self.on_log = lambda msg: print(f"[Host] {msg}")
        self.on_success = lambda img: None
        
        # Signer 也可能需要适配后的 keys，但目前 signer 主要用 s1/s2，adapt 不会删除旧key
        self.my_signer = ThresholdSigner(my_sk, 0)
        self.my_commitment = None
        
    def create_invitation(self):
        mgr = LanP2PManager() if self.lan_mode else P2PManager()
        idx = len(self.managers)
        # 传递 addr
        mgr.on_msg_callback = lambda t, p, a: self._handle_message(idx, t, p, a)
        mgr.start_as_server() 
        try:
            code = mgr.get_invitation_code()
            if code:
                with self.lock:
                    self.managers.append(mgr)
                    self.peers_data[idx] = {'verified': False}
                self.on_log(f"通道 {idx+1} 就绪，等待连接...")
                return code
        except Exception as e:
            self.on_log(f"创建邀请失败: {e}")
        return None

    def start_recovery(self, manifest, file_hash_bytes):
        with self.lock:
            if not self.managers:
                self.on_log("错误: 无连接")
                return
            valid_count = sum(1 for d in self.peers_data.values() if d.get('verified'))
            if valid_count == 0:
                self.on_log("错误: 没有已验证的协助者")
                return

            self.target_manifest = manifest
            self.target_file_hash = file_hash_bytes
            self.state = SessionState.WAITING_COMMITMENTS
            self.on_log(">>> 阶段 1: 请求承诺")

            self.my_commitment = self.my_signer.phase1_commitment()
            for mgr in self.managers:
                mgr.broadcast(ProtocolTypes.REQ_COMMITMENT, {})

    def _handle_message(self, idx, msg_type, payload, addr=None):
        with self.lock:
            try:
                if msg_type == ProtocolTypes.HELLO:
                    pk_received = json.loads(payload)
                    # Hex -> Bytes
                    if 'rho' in pk_received and isinstance(pk_received['rho'], str):
                        try: pk_received['rho'] = bytes.fromhex(pk_received['rho'])
                        except: pass
                    
                    # [关键适配 2] 远程公钥适配
                    pk_received = adapt_crypto_key(pk_received)

                    self.on_log(f"通道 {idx+1} 收到身份 HELLO (来源: {addr})")
                    
                    matched_entry = self._find_in_manifest(pk_received)
                    if matched_entry:
                        self.peers_data[idx]['pk'] = pk_received
                        self.peers_data[idx]['manifest_entry'] = matched_entry
                        self.peers_data[idx]['addr'] = addr
                        alias = matched_entry.get('owner_alias', 'Unknown')
                        self.on_log(f"通道 {idx+1} 身份确认: {alias}")
                        
                        # 发起握手 (使用适配后的 keys)
                        self.managers[idx].send_handshake_to_peer(addr, pk_received, self.my_sk)
                    else:
                        self.on_log(f"⚠️ 通道 {idx+1} 公钥不在清单中")

                elif msg_type == "HANDSHAKE":
                    if 'pk' in self.peers_data[idx]:
                        self.peers_data[idx]['verified'] = True
                        self.on_log(f"通道 {idx+1} 加密通道建立 ✅")

                elif msg_type == ProtocolTypes.RES_COMMITMENT:
                    if not self._is_peer_ready(idx): return
                    w = json.loads(payload['w'])
                    self.peers_data[idx]['w'] = w
                    self.on_log(f"收到 {idx+1} 号承诺")
                    self._check_phase1_complete()

                elif msg_type == ProtocolTypes.RES_RESPONSE:
                    z = json.loads(payload['z'])
                    self.peers_data[idx]['z'] = z
                    self.on_log(f"收到 {idx+1} 号签名")
                    self._check_phase2_complete()

                elif msg_type == ProtocolTypes.RES_SHARE:
                    share = self._deserialize_share_safe(payload['data'])
                    self.peers_data[idx]['share'] = share
                    self.on_log(f"收到 {idx+1} 号碎片")
                    self._check_phase3_complete()

            except Exception as e:
                self.on_log(f"Host处理异常: {e}")
                import traceback
                traceback.print_exc()

    def _is_peer_ready(self, idx):
        return self.peers_data.get(idx, {}).get('verified')

    def _find_in_manifest(self, pk_received):
        if not self.target_manifest:
             self.on_log("⚠️ Host 尚未加载 Manifest，使用宽松模式")
             return {'owner_alias': 'Unknown (Pre-check)'}
        target_str = json.dumps(pk_received['t'], sort_keys=True, cls=NumpyEncoder)
        for entry in self.target_manifest:
            if 'public_key_t' in entry:
                entry_str = json.dumps(entry['public_key_t'], sort_keys=True, cls=NumpyEncoder)
                if entry_str == target_str: return entry
        return None

    def _check_phase1_complete(self):
        active = [i for i, d in self.peers_data.items() if d.get('verified')]
        if not active: return
        for i in active:
            if 'w' not in self.peers_data[i]: return
        
        self.on_log(">>> 阶段 2: 广播挑战")
        all_w = [self.my_commitment] + [self.peers_data[i]['w'] for i in active]
        w_sum = self.aggregator.aggregate_w_shares(all_w)
        ts = int(time.time())
        pkg = {
            'm_hash': base64.b64encode(self.target_file_hash).decode(),
            'ts': ts,
            'w_sum': json.dumps(w_sum, cls=NumpyEncoder)
        }
        for mgr in self.managers:
            mgr.broadcast(ProtocolTypes.BROAD_CHALLENGE, pkg)
        self.state = SessionState.WAITING_RESPONSES
        msg = self.target_file_hash + ts.to_bytes(8, 'little')
        self.my_z = self.my_signer.phase2_response(msg, w_sum)

    def _check_phase2_complete(self):
        active = [i for i, d in self.peers_data.items() if d.get('verified')]
        for i in active:
            if 'z' not in self.peers_data[i]: return
        self.on_log(">>> 验证签名通过，请求碎片")
        for mgr in self.managers:
            mgr.broadcast(ProtocolTypes.REQ_SHARE, {})
        self.state = SessionState.RECONSTRUCTING

    def _check_phase3_complete(self):
        active = [i for i, d in self.peers_data.items() if d.get('verified')]
        for i in active:
            if 'share' not in self.peers_data[i]: return
        self.on_log(">>> 重构图像...")
        shares = [self.peers_data[i]['share'] for i in active]
        try:
            img = self.reconstructor.reconstruct_from_memory(shares)
            self.state = SessionState.FINISHED
            if self.on_success: self.on_success(img)
            self.on_log("🎉 恢复成功！")
        except Exception as e:
            self.on_log(f"重构失败: {e}")

    def _deserialize_share_safe(self, json_str):
        obj = json.loads(json_str)
        if 'data' in obj: obj['data'] = np.array(obj['data'], dtype=np.int64)
        return obj


# === Participant 逻辑 ===
class RecoveryParticipantSession:
    def __init__(self, my_sk, my_pk, lan_mode=False):
        self.mgr = LanP2PManager() if lan_mode else P2PManager()
        
        # [关键适配 3] 本地密钥适配
        self.my_sk = adapt_crypto_key(my_sk)
        self.my_pk = adapt_crypto_key(my_pk)
        
        self.host_pk = None 
        self.signer = ThresholdSigner(my_sk, 1) 
        self.orchestrator = Module3Orchestrator()
        self.lock = threading.Lock()
        self.local_carrier_path = None
        self.on_log = lambda msg: print(f"[Part] {msg}")
        self.on_approval_request = None 
        self.mgr.on_msg_callback = lambda t, p, a: self._handle_message(t, p)

    def join_session(self, invitation_code, carrier_path, host_pk_obj):
        with self.lock:
            self.local_carrier_path = carrier_path
            
            # [关键适配 4] Host 公钥适配 (如果是从文件加载的)
            self.host_pk = adapt_crypto_key(host_pk_obj)
            
            self.on_log("正在打洞连接...")
            if self.mgr.connect_via_code(invitation_code):
                self.on_log("网络连通，发送身份通告 (HELLO)...")
                # Client 发给 Server
                hello = {"type": ProtocolTypes.HELLO, "payload": json.dumps(self.my_pk, cls=NumpyEncoder)}
                self.mgr.rudp.send(json.dumps(hello).encode(), self.mgr.server_addr)
            else:
                self.on_log("连接失败")

    def _handle_message(self, msg_type, payload):
        with self.lock:
            try:
                if msg_type == "HANDSHAKE":
                    self.on_log("收到握手请求，验证 Host 签名...")
                    if not self.host_pk: return
                    
                    raw_handshake = base64.b64decode(payload) if isinstance(payload, str) else payload
                    # 此时 my_sk 和 host_pk 都已适配，应能成功解密
                    success = self.mgr.channel.setup_participant_session_verified(raw_handshake, self.my_sk, self.host_pk)
                    
                    if success: self.on_log("✅ 加密通道建立")
                    else: self.on_log("❌ 握手验证失败！")

                elif msg_type == ProtocolTypes.REQ_COMMITMENT:
                    self.on_log("生成承诺...")
                    w = self.signer.phase1_commitment()
                    self.mgr.send_secure_message(ProtocolTypes.RES_COMMITMENT, {'w': json.dumps(w, cls=NumpyEncoder)})

                elif msg_type == ProtocolTypes.BROAD_CHALLENGE:
                    self.on_log("收到挑战，请求授权...")
                    m_hash = base64.b64decode(payload['m_hash'])
                    ts = payload['ts']
                    w_sum = json.loads(payload['w_sum'])
                    msg = m_hash + int(ts).to_bytes(8, 'little')
                    
                    if self.on_approval_request and not self.on_approval_request(m_hash.hex()):
                        self.on_log("用户拒绝授权")
                        return

                    z = self.signer.phase2_response(msg, w_sum)
                    if z: self.mgr.send_secure_message(ProtocolTypes.RES_RESPONSE, {'z': json.dumps(z, cls=NumpyEncoder)})

                elif msg_type == ProtocolTypes.REQ_SHARE:
                    self.on_log("发送碎片...")
                    # 模拟: 实际使用 extract_share_bytes
                    enc_share = self.orchestrator.extract_share_bytes(self.local_carrier_path)
                    import pickle
                    cipher = pickle.loads(enc_share)
                    dec_bytes = LatticeEncryptor.decrypt_data(self.my_sk, cipher)
                    share_dict = pickle.loads(dec_bytes)
                    if 'data' in share_dict: share_dict['data'] = share_dict['data'].tolist()
                    
                    self.mgr.send_secure_message(ProtocolTypes.RES_SHARE, {'data': json.dumps(share_dict, cls=NumpyEncoder)})
                    self.on_log("碎片已发送")

            except Exception as e:
                self.on_log(f"Participant Error: {e}")
                import traceback
                traceback.print_exc()