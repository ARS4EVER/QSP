import threading
import time
import json
import base64
from src.network.p2p_manager import P2PManager
from src.crypto_lattice.keygen import KeyTool

# ==========================================
# 全局配置与密钥生成
# ==========================================
# 模拟两个用户: Alice (Client/发起方), Bob (Server/接收方)
print("[Test] 正在生成测试用的格密码密钥对...")
alice_keys = KeyTool.generate_keypair()
bob_keys = KeyTool.generate_keypair()

# 全局同步事件，确保 Alice 等到 Bob 启动后再连接
BOB_READY_EVENT = threading.Event()
SHARED_BOB_PORT = None

# ==========================================
# Server 逻辑 (Bob)
# ==========================================
def run_server_bob():
    """
    Bob 作为 Server 启动监听，等待连接并处理消息
    """
    print("    [Bob] 启动 P2P Server...")
    manager = P2PManager()
    
    # 1. 启动为 Server 模式 (这会自动绑定端口并启动 RUDP 接收线程)
    manager.start_as_server() 
    
    # 2. 获取端口并通知 Alice (模拟线下交换邀请码)
    global SHARED_BOB_PORT
    SHARED_BOB_PORT = manager.rudp.sock.getsockname()[1]
    
    # 通知 Alice 可以连接了
    BOB_READY_EVENT.set()
    
    # 定义收到消息的回调
    # 注意：新版 P2PManager 会传回 (msg_type, payload, addr)
    def on_message(msg_type, payload, addr):
        print(f"    [Bob] 收到消息 [{msg_type}] 来自 {addr}")
        
        if msg_type == "HANDSHAKE":
            print("    [Bob] 正在验证签名并建立会话...")
            
            # [关键] 获取对应来源的通道 (Manager 已不再持有单一 channel)
            # 这一步非常重要，因为 Server 可能同时连接多个人
            current_channel = manager._get_or_create_channel(addr)
            
            # 使用获取到的 channel 进行验证
            # Bob 使用自己的私钥 + Alice 的公钥来验证握手
            success = current_channel.setup_participant_session_verified(
                payload,        
                bob_keys[1],    
                alice_keys[0]   
            )
            
            if success:
                print("    [Bob] ✅ 通道建立成功！准备接收加密消息。")
                # 记录连接状态，标记该地址已通过身份认证
                manager.peers[addr]['established'] = True
            else:
                print("    [Bob] ❌ 握手验证失败！")
                
        elif msg_type == "CHAT":
            # 此时 payload 已经是解密后的明文 (dict 或 str)
            print(f"    [Bob] 🔓 解密成功! 内容: {payload}")

    # 注册回调
    manager.on_msg_callback = on_message
    
    # 保持运行 (模拟服务器持续在线)
    while True:
        time.sleep(1)

# ==========================================
# Client 逻辑 (Alice)
# ==========================================
def run_client_alice():
    """
    Alice 作为 Client 连接 Bob 并发送消息
    """
    print("[Alice] 启动 P2P Client...")
    manager = P2PManager()
    
    # 1. 等待 Bob 准备好
    print("[Alice] 等待 Bob 启动...")
    if not BOB_READY_EVENT.wait(timeout=10):
        print("[Alice] ❌ 连接超时: Bob 未响应")
        return
    
    # 2. 构造邀请码 (模拟从 Bob 处获取)
    # 注意：强制使用 127.0.0.1 进行本地回环测试
    fake_bob_info = {"ip": "127.0.0.1", "port": SHARED_BOB_PORT}
    bob_code = base64.b64encode(json.dumps(fake_bob_info).encode()).decode()
    
    print(f"[Alice] 连接目标: 127.0.0.1:{SHARED_BOB_PORT}")
    
    # [关键] 使用 connect_via_code 建立连接状态
    if manager.connect_via_code(bob_code):
        print("[Alice] 底层连接请求已发送")
    else:
        print("[Alice] 连接初始化失败")
        return
    
    time.sleep(1) # 等待 RUDP 打洞/握手完成
    
    # 3. 发起加密握手
    print(f"[Alice] 发起加密握手...")
    # Alice 使用 Bob 的公钥加密握手包，用自己的私钥签名
    manager.handshake_initiate(bob_keys[0], alice_keys[1])
    
    time.sleep(2) # 等待握手完成 (格密码计算和网络传输需要时间)
    
    # 4. 发送加密消息
    print(f"[Alice] 发送加密消息...")
    chat_payload = {"text": "Hello Bob! This is a secure message from Alice."}
    manager.send_secure_message("CHAT", chat_payload)
    
    # [关键修复] 给 RUDP 一点时间发送数据，也给 Bob 一点时间处理数据
    # 如果这里直接退出，Bob 可能还没来得及打印解密内容，程序就结束了
    print("[Alice] 消息已发送，等待 Bob 处理...")
    time.sleep(3) 
    
    print("[Alice] 测试结束")

# ==========================================
# 主程序
# ==========================================
if __name__ == "__main__":
    print("=== [测试 2] P2P 安全通道测试 (New Architecture) ===")
    
    # 启动 Bob (Daemon 线程会在主程序结束时自动退出)
    t_bob = threading.Thread(target=run_server_bob, daemon=True)
    t_bob.start()
    
    # 启动 Alice
    t_alice = threading.Thread(target=run_client_alice)
    t_alice.start()
    
    t_alice.join()
    print("=== Done ===")