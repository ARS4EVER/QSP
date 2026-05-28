import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
import threading
import json
import os
import base64
import hashlib
import socket
import time

from src.app.vault_crypto import ManifestCrypto
from src.app.manifest_key_manager import ManifestKeyManager

ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("dark-blue")


class MainWindow(ctk.CTk):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.p2p_node = app.p2p_node
        
        self._generate_local_identity()
        
        self.invite_code = app.invite_code
        self.selected_backup_file = None
        self.manifest_path = None
        self.connected_peers = {}
        
        self.title(f"QSP(当前节点: {self.app.node_id})")
        self.geometry("900x650")
        self.minsize(800, 600)
        
        logo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "image", "logo.png")
        if os.path.exists(logo_path):
            try:
                icon_image = Image.open(logo_path)
                self.iconphoto(True, icon_image)
            except:
                pass
        
        # 初始化应用层 (创建 UIBridge 等)
        self._init_app_layer()
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color="#f0f0f0")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)
        
        self.logo_label = ctk.CTkLabel(
            self.sidebar, 
            text="QSP", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.btn_tab_net = ctk.CTkButton(
            self.sidebar, 
            text="身份与网络", 
            command=self.show_net_tab,
            fg_color="#333333",
            hover_color="#555555",
            text_color="white"
        )
        self.btn_tab_net.grid(row=1, column=0, padx=20, pady=10)
        
        self.btn_tab_backup = ctk.CTkButton(
            self.sidebar, 
            text="文件备份", 
            command=self.show_backup_tab,
            fg_color="#444444",
            hover_color="#666666",
            text_color="white"
        )
        self.btn_tab_backup.grid(row=2, column=0, padx=20, pady=10)
        
        self.btn_tab_recovery = ctk.CTkButton(
            self.sidebar, 
            text="文件恢复", 
            command=self.show_recovery_tab,
            fg_color="#555555",
            hover_color="#777777",
            text_color="white"
        )
        self.btn_tab_recovery.grid(row=3, column=0, padx=20, pady=10)
        
        self.status_label = ctk.CTkLabel(
            self.sidebar,
            text="状态: 就绪",
            text_color="#666666",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.grid(row=4, column=0, padx=20, pady=10)
        
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="white")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        # 核心修改：预先初始化所有页面 Frame，利用 grid 将它们堆叠在一起
        self.net_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.backup_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.recovery_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        
        for frame in (self.net_frame, self.backup_frame, self.recovery_frame):
            frame.grid(row=0, column=0, sticky="nsew")
            
        # 一次性构建所有界面的 UI 组件，避免后续销毁
        self._build_net_tab()
        self._build_backup_tab()
        self._build_recovery_tab()
        
        # 默认展示网络页面
        self.show_net_tab()
        self.update_status("系统初始化完成")

        self._original_on_connected = None

        def on_any_connected(addr):
            # 将地址转换为统一的字符串格式，避免重复计数
            addr_str = str(addr)
            
            # 检查是否已连接
            if addr_str in self.connected_peers:
                print(f"[MainWindow] 节点 {addr} 已连接，跳过重复计数")
                return
            
            self.connected_peers[addr_str] = True
            print(f"[MainWindow] 新增连接节点: {addr}")
            
            # 因使用堆叠布局，组件永不被销毁，此处回调永远安全有效
            self.ui_bridge.run_in_main_thread(
                self.lbl_peer_list.configure,
                text=f"已连接节点: {len(self.connected_peers)}",
                text_color="#2FA572"
            )
            self.ui_bridge.safe_update_net_status(f"安全链接建立: {addr}", "#2FA572")
            if hasattr(self.p2p_node, 'secure_links') and addr in self.p2p_node.secure_links:
                self.p2p_node.secure_links[addr].on_app_data_received = lambda node_id, data: \
                    self.p2p_node.router.route_message(node_id, data)
            
            # 延迟发送清单公钥，确保安全链接完全建立
            threading.Thread(target=self._delayed_send_manifest_key, args=(addr,), daemon=True).start()
        
        self.p2p_node.on_physically_connected = on_any_connected
        
        # 注册连接断开回调
        if hasattr(self.p2p_node, 'ui_callback'):
            original_callback = self.p2p_node.ui_callback
            
            def on_peer_disconnected(event, node_id):
                if event == 'peer_disconnected':
                    # 从已连接列表中移除
                    for addr_str in list(self.connected_peers.keys()):
                        if node_id in addr_str or addr_str in node_id:
                            del self.connected_peers[addr_str]
                            print(f"[MainWindow] 节点 {node_id} 已断开连接")
                            break
                    # 更新UI显示
                    self.ui_bridge.run_in_main_thread(
                        self.lbl_peer_list.configure,
                        text=f"已连接节点: {len(self.connected_peers)}",
                        text_color="#666666"
                    )
            
            self.p2p_node.ui_callback = on_peer_disconnected
    
    def _delayed_send_manifest_key(self, peer_addr):
        """延迟发送清单公钥，确保安全链接完全建立"""
        time.sleep(1)  # 延迟1秒确保安全握手完成
        self._send_manifest_public_key(peer_addr)
    
    def _send_manifest_public_key(self, peer_addr):
        """发送清单公钥给已连接的节点"""
        try:
            from src.app.app_protocol import AppMessageV2, AppCmdV2
            import base64
            
            manifest_key_manager = self._get_manifest_key_manager()
            if manifest_key_manager:
                my_public_key = manifest_key_manager.get_public_key()
                payload = {
                    "manifest_pk": base64.b64encode(my_public_key).decode('utf-8')
                }
                msg = AppMessageV2(
                    cmd=AppCmdV2.MANIFEST_KEY_EXCHANGE,
                    sender_id=self.app.node_id,
                    payload=payload
                )
                
                # 尝试多种方式发送
                sent = False
                
                # 方式1：通过 secure_links 发送
                if hasattr(self.p2p_node, 'secure_links') and peer_addr in self.p2p_node.secure_links:
                    link = self.p2p_node.secure_links[peer_addr]
                    if hasattr(link, 'send_reliable'):
                        link.send_reliable(msg.encode())
                        print(f"[MainWindow] 已发送清单公钥给 {peer_addr}")
                        sent = True
                
                # 方式2：通过 secure_link 发送（单连接模式）
                if not sent and hasattr(self.p2p_node, 'secure_link'):
                    link = self.p2p_node.secure_link
                    if hasattr(link, 'send_reliable'):
                        link.send_reliable(msg.encode())
                        print(f"[MainWindow] 已发送清单公钥给 {peer_addr} (通过 secure_link)")
                        sent = True
                
                if not sent:
                    print(f"[MainWindow] 无法发送清单公钥：未找到有效的安全链接")
        except Exception as e:
            print(f"[MainWindow] 发送清单公钥失败: {e}")

    def _init_app_layer(self):
        from src.app.ui_bridge import UIBridge
        from src.app.app_router import AppRouter
        from src.app.app_protocol import AppCmd, AppCmdV2
        from src.app.backup_manager import BackupManager
        from src.app.recovery_manager import RecoveryManager
        from src.app.vault_crypto import VaultCrypto, ManifestCrypto
        from src.core.recovery_participant import RecoveryParticipant
        
        self.ui_bridge = UIBridge(self)
        self.p2p_node.router.ui_invoker = self.ui_bridge.run_in_main_thread
        
        from src.config import SHARES_DIR
        
        vault_password = self.app.vault_password
        
        if not vault_password:
            messagebox.showerror("严重错误", "未获取到本地凭证，即将退出。")
            self.destroy()
            return

        self.vault_crypto = VaultCrypto(vault_password)
        self.backup_mgr = BackupManager(p2p_node=self.p2p_node, vault_crypto=self.vault_crypto, vault_dir=SHARES_DIR)
        self.recovery_mgr = RecoveryManager(p2p_node=self.p2p_node, vault_crypto=self.vault_crypto, vault_dir=SHARES_DIR)

        self.recovery_participant = RecoveryParticipant(p2p_node=self.p2p_node, vault_crypto=self.vault_crypto)
        self.recovery_participant.register_handlers()
        self.manifest_crypto = None

        self.p2p_node.router.register_handler(AppCmdV2.SHARE_PUSH, self.backup_mgr.handle_incoming_share)
        self.p2p_node.router.register_handler(AppCmdV2.PULL_REQ, self.recovery_mgr.handle_pull_request)
        self.p2p_node.router.register_handler(AppCmdV2.PULL_RESP, self.recovery_mgr.handle_pull_response)
        self.p2p_node.router.register_handler(AppCmdV2.CHALLENGE_RESP, self.recovery_mgr.handle_challenge_response)
        self.p2p_node.router.register_handler(AppCmdV2.MANIFEST_KEY_EXCHANGE, self._handle_manifest_key_exchange)
        
        self.recovery_mgr.on_progress_update = self._on_recovery_progress
        self.recovery_mgr.on_recovery_success = self._on_recovery_success
        self.recovery_mgr.on_recovery_failed = self._on_recovery_failed

    def _get_manifest_key_manager(self):
        """获取清单密钥管理器"""
        if hasattr(self, 'manifest_key_manager') and self.manifest_key_manager is not None:
            return self.manifest_key_manager
        
        if hasattr(self.vault_crypto, 'password'):
            password = self.vault_crypto.password.decode('utf-8') if isinstance(self.vault_crypto.password, bytes) else self.vault_crypto.password
            self.manifest_key_manager = ManifestKeyManager(password)
            return self.manifest_key_manager
        
        return None
    
    def _handle_manifest_key_exchange(self, verified_source_id: str, msg):
        """处理接收到的清单公钥"""
        try:
            import base64
            
            manifest_pk_b64 = msg.payload.get("manifest_pk")
            if manifest_pk_b64:
                peer_manifest_pk = base64.b64decode(manifest_pk_b64)
                
                # 持久化保存对方的清单公钥（节点身份指纹 -> 清单公钥）
                manifest_key_manager = self._get_manifest_key_manager()
                if manifest_key_manager:
                    manifest_key_manager.save_peer_public_key(verified_source_id, peer_manifest_pk)
                    print(f"[MainWindow] 已持久化保存节点 {verified_source_id[:8]} 的清单公钥")
                
                # 同时临时保存到安全通道（供当前会话使用）
                if hasattr(self.p2p_node, 'secure_links'):
                    for addr, link in self.p2p_node.secure_links.items():
                        if hasattr(link, 'channel'):
                            link.channel.peer_manifest_pk = peer_manifest_pk
                            print(f"[MainWindow] 已临时保存对方清单公钥到通道")
        except Exception as e:
            print(f"[MainWindow] 处理清单公钥失败: {e}")
    
    def _get_manifest_crypto(self):
        """从金库密码派生清单加密密钥（向后兼容）"""
        if self.manifest_crypto is not None:
            return self.manifest_crypto
        
        if hasattr(self.vault_crypto, 'password'):
            self.manifest_crypto = ManifestCrypto(self.vault_crypto.password)
            return self.manifest_crypto
        
        return None

    def _on_recovery_progress(self, file_hash, current, total, progress=None, status=""):
        if hasattr(self, 'recovery_progress'):
            if progress is not None:
                self.ui_bridge.safe_update_progress(int(progress), 100)
            else:
                self.ui_bridge.safe_update_progress(current, total)
        if hasattr(self, 'lbl_recovery_status'):
            status_text = status if status else f"收集份额: {current}/{total}"
            self.ui_bridge.run_in_main_thread(
                self.lbl_recovery_status.configure,
                text=status_text,
                text_color="#E5A50A"
            )

    def _on_recovery_success(self, file_hash, restored_path):
        self.ui_bridge.safe_show_info("成功", f"文件已重构至:\n{restored_path}")
        self.ui_bridge.safe_update_net_status("文件恢复完成", "#2FA572")
        self.ui_bridge.run_in_main_thread(
            self.lbl_recovery_status.configure, text="秘密重构成功!", text_color="#2FA572"
        )
        self.ui_bridge.safe_update_progress(1, 1)
        self.ui_bridge.safe_set_action_buttons_state("normal")

    def _on_recovery_failed(self, file_hash, error_msg):
        self.ui_bridge.safe_show_error("恢复失败", error_msg)
        self.ui_bridge.safe_update_net_status("恢复失败", "#C8504B")
        self.ui_bridge.run_in_main_thread(
            self.lbl_recovery_status.configure, text="恢复中断", text_color="#C8504B"
        )
        self.ui_bridge.safe_update_progress(0, 1)
        self.ui_bridge.safe_set_action_buttons_state("normal")

    def _generate_local_identity(self):
        try:
            from src.crypto_lattice.encryptor import KyberKEM
            
            self.kyber_pk, self.kyber_sk = KyberKEM.generate_keypair()

            self.dil_pk = self.app.keypair["pk"]
            self.dil_sk = self.app.keypair["sk"]
            
        except Exception as e:
            messagebox.showerror("密码学引擎错误", f"无法生成抗量子密钥: {e}")
            self.kyber_pk = b""
            self.dil_pk = b""
            self.invite_code = "QSP-Invite://error"

    def update_status(self, message: str, color: str = "gray"):
        self.status_label.configure(text=f"状态: {message}", text_color=color)

    # 移除原有的 clear_main_frame() 方法

    def _build_net_tab(self):
        # 绑定到 net_frame
        ctk.CTkLabel(
            self.net_frame, 
            text="本机专属邀请码 (包含公钥指纹与坐标):", 
            font=ctk.CTkFont(size=14),
            text_color="#333333"
        ).pack(pady=(40, 10))
        
        self.entry_my_code = ctk.CTkEntry(self.net_frame, width=600, fg_color="#f8f8f8", text_color="#333333", border_color="#cccccc")
        self.entry_my_code.insert(0, self.invite_code)
        self.entry_my_code.configure(state='readonly')
        self.entry_my_code.pack(pady=10)
        
        ctk.CTkButton(
            self.net_frame, 
            text="复制邀请码", 
            command=self.copy_code,
            fg_color="#666666",
            hover_color="#888888",
            text_color="white"
        ).pack(pady=10)
        
        ctk.CTkLabel(
            self.net_frame, 
            text="连接远端节点 (粘贴邀请码):", 
            font=ctk.CTkFont(size=14),
            text_color="#333333"
        ).pack(pady=(40, 10))
        
        self.entry_target_code = ctk.CTkEntry(self.net_frame, width=600, fg_color="#f8f8f8", text_color="#333333", border_color="#cccccc")
        self.entry_target_code.pack(pady=10)
        
        ctk.CTkButton(
            self.net_frame, 
            text="发起UDP穿透与安全握手", 
            fg_color="#444444", 
            hover_color="#666666",
            text_color="white",
            command=self.connect_peer
        ).pack(pady=20)
        
        self.lbl_net_status = ctk.CTkLabel(
            self.net_frame, 
            text=f"网络状态: 监听端口 {self.p2p_node.port}",
            text_color="#666666"
        )
        self.lbl_net_status.pack(pady=20)
        
        self.lbl_peer_list = ctk.CTkLabel(
            self.net_frame,
            text="已连接节点: 0",
            text_color="#666666"
        )
        self.lbl_peer_list.pack(pady=10)

    def _build_backup_tab(self):
        # 绑定到 backup_frame
        ctk.CTkButton(
            self.backup_frame, 
            text="选择待保护机密文件", 
            command=self.select_file,
            fg_color="#666666",
            hover_color="#888888",
            text_color="white"
        ).pack(pady=(50, 20))
        
        self.lbl_file = ctk.CTkLabel(
            self.backup_frame, 
            text="未选择文件", 
            text_color="#666666"
        )
        self.lbl_file.pack(pady=10)
        
        param_frame = ctk.CTkFrame(self.backup_frame, fg_color="transparent")
        param_frame.pack(pady=30)
        
        ctk.CTkLabel(param_frame, text="总节点数 (N):", text_color="#333333").grid(row=0, column=0, padx=10)
        self.entry_n = ctk.CTkEntry(param_frame, width=60, fg_color="#f8f8f8", text_color="#333333", border_color="#cccccc")
        self.entry_n.insert(0, "5")
        self.entry_n.grid(row=0, column=1, padx=10)
        
        ctk.CTkLabel(param_frame, text="恢复门限 (T):", text_color="#333333").grid(row=0, column=2, padx=10)
        self.entry_t = ctk.CTkEntry(param_frame, width=60, fg_color="#f8f8f8", text_color="#333333", border_color="#cccccc")
        self.entry_t.insert(0, "3")
        self.entry_t.grid(row=0, column=3, padx=10)
        
        self.btn_execute_backup = ctk.CTkButton(
            self.backup_frame, 
            text="执行机密文件分割与加密", 
            fg_color="#555555", 
            hover_color="#777777",
            text_color="white",
            command=self.execute_backup
        )
        self.btn_execute_backup.pack(pady=40)
        
        self.backup_progress = ctk.CTkProgressBar(self.backup_frame, width=400, progress_color="#666666")
        self.backup_progress.set(0)
        self.backup_progress.pack(pady=20)
        
        self.lbl_backup_status = ctk.CTkLabel(
            self.backup_frame,
            text="等待操作...",
            text_color="#666666"
        )
        self.lbl_backup_status.pack(pady=10)

    def _build_recovery_tab(self):
        ctk.CTkLabel(
            self.recovery_frame, 
            text="选择可恢复的机密文件 (基于本地权限解密):", 
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#333333"
        ).pack(pady=(40, 10))
        
        self.manifest_var = ctk.StringVar(value="正在扫描与验证权限...")
        self.opt_manifest = ctk.CTkOptionMenu(
            self.recovery_frame,
            variable=self.manifest_var,
            values=["暂无可用清单"],
            command=self._on_manifest_select,
            width=500,
            fg_color="#f8f8f8",
            text_color="#333333",
            button_color="#888888",
            button_hover_color="#666666"
        )
        self.opt_manifest.pack(pady=10)

        ctk.CTkButton(
            self.recovery_frame, 
            text="从外部手动导入密文 Manifest", 
            command=self.load_manifest,
            fg_color="#666666",
            hover_color="#888888",
            text_color="white"
        ).pack(pady=(10, 20))
        
        self.lbl_manifest = ctk.CTkLabel(
            self.recovery_frame, 
            text="当前未锁定目标清单", 
            text_color="#666666"
        )
        self.lbl_manifest.pack(pady=10)
        
        self.recovery_progress = ctk.CTkProgressBar(self.recovery_frame, width=400, progress_color="#666666")
        self.recovery_progress.set(0)
        self.recovery_progress.pack(pady=30)
        
        self.btn_execute_recovery = ctk.CTkButton(
            self.recovery_frame, 
            text="执行身份签名验证与文件重构", 
            fg_color="#444444", 
            hover_color="#666666",
            text_color="white",
            command=self.execute_recovery
        )
        self.btn_execute_recovery.pack(pady=20)
        
        self.lbl_recovery_status = ctk.CTkLabel(
            self.recovery_frame,
            text="等待操作...",
            text_color="#666666"
        )
        self.lbl_recovery_status.pack(pady=10)

    # UI 切换与桥接动态绑定
    def show_net_tab(self):
        self.net_frame.tkraise()
        if hasattr(self, 'ui_bridge'):
            self.ui_bridge.bind_widgets(
                lbl_net_status=self.lbl_net_status,
                progress_bar=None,
                btn_backup=None,
                btn_recovery=None
            )

    def show_backup_tab(self):
        self.backup_frame.tkraise()
        if hasattr(self, 'ui_bridge'):
            self.ui_bridge.bind_widgets(
                lbl_net_status=self.lbl_net_status,
                progress_bar=self.backup_progress,
                btn_backup=self.btn_execute_backup,
                btn_recovery=None
            )

    def show_recovery_tab(self):
        self.recovery_frame.tkraise()
        self._refresh_local_manifests()
        if hasattr(self, 'ui_bridge'):
            self.ui_bridge.bind_widgets(
                lbl_net_status=self.lbl_net_status,
                progress_bar=self.recovery_progress,
                btn_backup=None,
                btn_recovery=self.btn_execute_recovery
            )

    def _refresh_local_manifests(self):
        import glob
        from src.config import SHARES_DIR, MANIFESTS_DIR
        from cryptography.exceptions import InvalidTag
        
        # 确保目录存在
        os.makedirs(SHARES_DIR, exist_ok=True)
        os.makedirs(MANIFESTS_DIR, exist_ok=True)
        
        # 获取 SHARES_DIR 目录下所有的 .enc 文件
        enc_files = glob.glob(os.path.join(SHARES_DIR, "*.enc"))
        print(f"[_refresh_local_manifests] 在 {SHARES_DIR} 中找到 {len(enc_files)} 个 .enc 文件")
        
        display_values = []
        self.manifest_data_map = {}
        self.manifest_path_map = {}  # 新增：用于存储文件路径
        
        for enc_path in enc_files:
            try:
                filename = os.path.basename(enc_path)
                file_stat = os.stat(enc_path)
                file_size = file_stat.st_size
                print(f"[_refresh_local_manifests] 处理文件: {filename}, 大小: {file_size} Bytes")
                
                with open(enc_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # 尝试解密清单
                decrypted_bytes = None
                manifest_dict = None
                
                # 首先尝试密钥封装机制解密（版本 V3）
                if len(encrypted_data) > 0 and encrypted_data[0:1] == b'\x03':
                    manifest_key_manager = self._get_manifest_key_manager()
                    if manifest_key_manager:
                        try:
                            decrypted_bytes = manifest_key_manager.decrypt_manifest(encrypted_data)
                            print(f"[_refresh_local_manifests] 成功使用清单密钥管理器解密: {filename}")
                        except Exception as e:
                            print(f"[_refresh_local_manifests] 清单密钥管理器解密失败: {e}")
                
                # 如果版本不对，尝试用 ManifestCrypto 解密（使用金库密码）
                if not decrypted_bytes:
                    manifest_crypto = self._get_manifest_crypto()
                    if manifest_crypto:
                        try:
                            decrypted_bytes = manifest_crypto.decrypt_manifest(encrypted_data)
                            print(f"[_refresh_local_manifests] 成功使用 ManifestCrypto 解密: {filename}")
                        except Exception as e:
                            print(f"[_refresh_local_manifests] ManifestCrypto 解密失败: {e}")
                
                # 如果仍然失败，尝试用 vault_crypto 的清单解密方法
                if not decrypted_bytes:
                    try:
                        decrypted_bytes = self.vault_crypto.decrypt_manifest(encrypted_data)
                        print(f"[_refresh_local_manifests] 成功使用 vault_crypto.decrypt_manifest 解密: {filename}")
                    except InvalidTag:
                        try:
                            decrypted_bytes = self.vault_crypto.decrypt_data(encrypted_data)
                            print(f"[_refresh_local_manifests] 成功使用 vault_crypto.decrypt_data 解密: {filename}")
                        except Exception as e:
                            print(f"[_refresh_local_manifests] vault_crypto 解密失败: {e}")
                    except Exception as e:
                        print(f"[_refresh_local_manifests] vault_crypto.decrypt_manifest 异常: {e}")
                
                if decrypted_bytes:
                    manifest_dict = json.loads(decrypted_bytes.decode('utf-8'))
                    print(f"[_refresh_local_manifests] 成功解析清单 JSON: {filename}")
                
                if manifest_dict:
                    # 兼容旧格式和新格式的字段名
                    name = manifest_dict.get("original_filename", manifest_dict.get("filename", "未知文件"))
                    manifest_file_size = manifest_dict.get("file_size", file_size)
                    display_name = f"{name} ({manifest_file_size} Bytes) - {filename}"
                    
                    display_values.append(display_name)
                    self.manifest_data_map[display_name] = manifest_dict
                    self.manifest_path_map[display_name] = enc_path  # 保存文件路径
                else:
                    # 如果无法解密，仍然显示文件名（标记为加密文件）
                    display_name = f"{filename} (加密文件, {file_size} Bytes)"
                    display_values.append(display_name)
                    self.manifest_path_map[display_name] = enc_path  # 保存文件路径
                    print(f"[_refresh_local_manifests] 无法解密文件，仍将其显示在列表中: {filename}")
                
            except Exception as e:
                print(f"[_refresh_local_manifests] 处理文件 {enc_path} 时出错: {e}")
                # 即使出错，仍然尝试只显示文件名
                try:
                    filename = os.path.basename(enc_path)
                    file_stat = os.stat(enc_path)
                    file_size = file_stat.st_size
                    display_name = f"{filename} (文件, {file_size} Bytes)"
                    display_values.append(display_name)
                    self.manifest_path_map[display_name] = enc_path
                except:
                    pass
                continue
                
        if display_values:
            self.opt_manifest.configure(values=display_values, state="normal")
            self.manifest_var.set(display_values[0])
            self._on_manifest_select(display_values[0])
        else:
            self.opt_manifest.configure(values=["暂无可用清单文件"], state="disabled")
            self.manifest_var.set("暂无可用清单文件")
            self.lbl_manifest.configure(text="未锁定清单", text_color="#666666")
            self.active_manifest_dict = None
            self.manifest_path = None

    def _on_manifest_select(self, choice):
        self.active_manifest_dict = None
        self.manifest_path = None
        
        if hasattr(self, 'manifest_data_map') and choice in self.manifest_data_map:
            self.active_manifest_dict = self.manifest_data_map[choice]
            if hasattr(self, 'manifest_path_map') and choice in self.manifest_path_map:
                self.manifest_path = self.manifest_path_map[choice]
            self.lbl_manifest.configure(text=f"已验证并锁定机密文件网络清单:\n{choice}", text_color="#2FA572")
        elif hasattr(self, 'manifest_path_map') and choice in self.manifest_path_map:
            # 这是一个加密文件，未成功解密，但我们仍然保存路径
            self.manifest_path = self.manifest_path_map[choice]
            self.lbl_manifest.configure(text=f"已选择加密清单文件:\n{choice}\n(执行恢复时将尝试解密)", text_color="#E5A50A")

    def copy_code(self):
        self.clipboard_clear()
        self.clipboard_append(self.entry_my_code.get())
        messagebox.showinfo("成功", "本机邀请码已复制")
        self.update_status("邀请码已复制", "#2FA572")

    def connect_peer(self):
        code = self.entry_target_code.get().strip()
        if not code:
            messagebox.showwarning("警告", "请输入邀请码")
            return
        
        if not code.startswith("QSP-Invite://"):
            messagebox.showwarning("警告", "无效的邀请码格式")
            return
        
        self.lbl_net_status.configure(
            text="状态: 正在向目标节点发送 UDP 穿透包并执行 Kyber 握手...", 
            text_color="#E5A50A"
        )
        
        def do_connect():
            try:
                self.p2p_node.static_sk = self.dil_sk
                self.p2p_node._is_initiator = True
                self.p2p_node.connect_via_invite(code, 1000)
                
            except Exception as e:
                self.ui_bridge.safe_show_error("连接失败", f"无法建立安全连接: {e}")
                self.ui_bridge.safe_update_net_status("连接失败", "#C8504B")
        
        threading.Thread(target=do_connect, daemon=True).start()

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.selected_backup_file = path
            filename = os.path.basename(path)
            self.lbl_file.configure(text=filename)

    def execute_backup(self):
        filepath = self.lbl_file.cget("text")
        if not filepath or filepath == "未选择文件" or not os.path.exists(filepath):
            filepath = getattr(self, 'selected_backup_file', None)
            if not filepath or not os.path.exists(filepath):
                messagebox.showerror("错误", "请先选择有效的文件！")
                return
        
        try:
            n = int(self.entry_n.get())
            t = int(self.entry_t.get())
            if not (1 < t <= n):
                messagebox.showwarning("警告", "门限值必须满足 1 < T <= N")
                return
        except ValueError:
            messagebox.showwarning("警告", "N 和 T 必须是整数")
            return
        
        self.update_status("正在执行文件备份与网络分发...", "#E5A50A")
        self.lbl_backup_status.configure(text="正在启动备份管理器...", text_color="#E5A50A")
        self.backup_progress.set(0.2)
        self.ui_bridge.safe_set_action_buttons_state("disabled")
        
        def do_backup():
            try:
                manifest_path = self.backup_mgr.execute_backup(filepath, n, t)
                
                self.ui_bridge.safe_update_progress(1.0, 1.0)
                self.ui_bridge.run_in_main_thread(self.update_status, "文件备份完成", "#2FA572")
                self.ui_bridge.run_in_main_thread(
                    self.lbl_backup_status.configure, text="网络分发与备份完成!", text_color="#2FA572"
                )
                self.ui_bridge.safe_show_info(
                    "成功", 
                    f"文件已成功分割为 {n} 份 (恢复门限 {t})\n并已通过抗量子信道分发。\n\n元数据清单已保存至:\n{manifest_path}"
                )
            except Exception as e:
                self.ui_bridge.run_in_main_thread(
                    self.lbl_backup_status.configure, text=f"错误: {str(e)}", text_color="#C8504B"
                )
                self.ui_bridge.run_in_main_thread(self.update_status, "备份失败", "#C8504B")
                self.ui_bridge.safe_show_error("备份失败", f"处理或分发文件份额时发生错误: {e}")
            finally:
                self.ui_bridge.safe_set_action_buttons_state("normal")
        
        threading.Thread(target=do_backup, daemon=True).start()

    def load_manifest(self):
        path = filedialog.askopenfilename(filetypes=[
            ("Encrypted Manifest", "*.enc"),
            ("JSON Files", "*.json")
        ])
        if path:
            self.manifest_path = path
            self.active_manifest_dict = None
            filename = os.path.basename(path)
            
            if path.endswith('.enc'):
                self.is_encrypted_manifest = True
                self.manifest_var.set(f"导入密文清单: {filename}")
                self.lbl_manifest.configure(text=f"已加载密文清单 (执行时解密):\n{path}", text_color="#E5A50A")
            else:
                self.is_encrypted_manifest = False
                self.manifest_var.set(f"导入明文清单: {filename}")
                self.lbl_manifest.configure(text=f"已加载明文清单:\n{path}", text_color="#E5A50A")

    def execute_recovery(self):
        manifest_dict = getattr(self, 'active_manifest_dict', None)
        manifest_path = getattr(self, 'manifest_path', None)
        is_encrypted = getattr(self, 'is_encrypted_manifest', False)
        
        if not manifest_dict and (not manifest_path or not os.path.exists(manifest_path)):
            messagebox.showerror("错误", "无有效的恢复清单目标！")
            return
        
        self.update_status("正在执行文件恢复与网络寻呼...", "#E5A50A")
        self.lbl_recovery_status.configure(text="正在向 P2P 网络广播拉取请求...", text_color="#E5A50A")
        self.recovery_progress.set(0.1)
        self.ui_bridge.safe_set_action_buttons_state("disabled")
        
        def do_recovery():
            import tempfile
            temp_path = None
            try:
                if manifest_dict:
                    fd, temp_path = tempfile.mkstemp(suffix=".json")
                    with os.fdopen(fd, 'w', encoding='utf-8') as f:
                        json.dump(manifest_dict, f)
                    target_path = temp_path
                elif is_encrypted:
                    with open(manifest_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    decrypted_bytes = None
                    
                    # 首先尝试使用清单密钥管理器解密（版本 V3）
                    if len(encrypted_data) > 0 and encrypted_data[0:1] == b'\x03':
                        manifest_key_manager = self._get_manifest_key_manager()
                        if manifest_key_manager:
                            try:
                                decrypted_bytes = manifest_key_manager.decrypt_manifest(encrypted_data)
                            except:
                                pass
                    
                    # 如果密钥管理器失败，尝试用 ManifestCrypto 解密（使用金库密码）
                    if not decrypted_bytes:
                        manifest_crypto = self._get_manifest_crypto()
                        if manifest_crypto:
                            try:
                                decrypted_bytes = manifest_crypto.decrypt_manifest(encrypted_data)
                            except:
                                pass
                    
                    # 如果仍然失败，尝试用 vault_crypto
                    if not decrypted_bytes:
                        try:
                            decrypted_bytes = self.vault_crypto.decrypt_manifest(encrypted_data)
                        except:
                            try:
                                decrypted_bytes = self.vault_crypto.decrypt_data(encrypted_data)
                            except:
                                raise ValueError("无法解密清单文件，请确认密钥正确！")
                    
                    manifest_dict_from_enc = json.loads(decrypted_bytes.decode('utf-8'))
                    
                    fd, temp_path = tempfile.mkstemp(suffix=".json")
                    with os.fdopen(fd, 'w', encoding='utf-8') as f:
                        json.dump(manifest_dict_from_enc, f)
                    target_path = temp_path
                else:
                    target_path = manifest_path

                self.recovery_mgr.execute_recovery(target_path)
                
            except Exception as e:
                self.ui_bridge.run_in_main_thread(
                    self.lbl_recovery_status.configure, text=f"启动错误: {str(e)}", text_color="#C8504B"
                )
                self.ui_bridge.run_in_main_thread(self.update_status, "恢复启动失败", "#C8504B")
                self.ui_bridge.safe_show_error("恢复阻断", f"无法启动文件重构: {e}")
                self.ui_bridge.safe_set_action_buttons_state("normal")
            finally:
                if temp_path and os.path.exists(temp_path):
                    try:
                        with open(temp_path, "ba+") as f:
                            length = f.tell()
                            f.seek(0)
                            f.write(b'\x00' * length)
                        os.remove(temp_path)
                    except:
                        pass
        
        threading.Thread(target=do_recovery, daemon=True).start()
