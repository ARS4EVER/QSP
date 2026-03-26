import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import json
import os
import base64
import hashlib
import socket
import time

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


class MainWindow:
    def __init__(self, root, p2p_node, app, invite_code):
        self.root = root
        self.p2p_node = p2p_node
        self.app = app
        
        self._generate_local_identity()
        
        self.invite_code = invite_code
        self.selected_backup_file = None
        self.manifest_path = None
        self.connected_peers = {}
        
        self._init_app_layer()
        
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        
        self.sidebar = ctk.CTkFrame(root, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)
        
        self.logo_label = ctk.CTkLabel(
            self.sidebar, 
            text="QSP System", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.btn_tab_net = ctk.CTkButton(
            self.sidebar, 
            text="身份与网络", 
            command=self.show_net_tab
        )
        self.btn_tab_net.grid(row=1, column=0, padx=20, pady=10)
        
        self.btn_tab_backup = ctk.CTkButton(
            self.sidebar, 
            text="资产备份", 
            command=self.show_backup_tab
        )
        self.btn_tab_backup.grid(row=2, column=0, padx=20, pady=10)
        
        self.btn_tab_recovery = ctk.CTkButton(
            self.sidebar, 
            text="资产恢复", 
            command=self.show_recovery_tab
        )
        self.btn_tab_recovery.grid(row=3, column=0, padx=20, pady=10)
        
        self.status_label = ctk.CTkLabel(
            self.sidebar,
            text="状态: 就绪",
            text_color="gray",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.grid(row=4, column=0, padx=20, pady=10)
        
        self.main_frame = ctk.CTkFrame(root, corner_radius=10)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)
        
        self.show_net_tab()
        self.update_status("系统初始化完成")
        
        # 保存原始的服务端连接回调
        self._original_on_connected = None
        
        # 设置统一的连接回调
        def on_any_connected(addr):
            self.connected_peers[addr] = True
            self.ui_bridge.run_in_main_thread(
                self.lbl_peer_list.configure,
                text=f"已连接节点: {len(self.connected_peers)}",
                text_color="#2FA572"
            )
            self.ui_bridge.safe_update_net_status(f"安全链接建立: {addr}", "#2FA572")
            # 设置数据接收回调
            if hasattr(self.p2p_node, 'secure_links') and addr in self.p2p_node.secure_links:
                self.p2p_node.secure_links[addr].on_data_received = lambda data: \
                    self.app_router.dispatch_network_data(addr, data)
        
        self.p2p_node.on_physically_connected = on_any_connected

    def _init_app_layer(self):
        from src.app.ui_bridge import UIBridge
        from src.app.app_router import AppRouter
        from src.app.app_protocol import AppCmd
        from src.app.backup_manager import BackupManager
        from src.app.recovery_manager import RecoveryManager
        
        self.ui_bridge = UIBridge(self.root)
        self.app_router = AppRouter(ui_invoker=self.ui_bridge.run_in_main_thread)
        
        vault_dir = os.path.join(os.path.dirname(__file__), "..", "data", "shares")
        
        # 【核心修改】引入简单的密码交互，激活端点安全防御
        dialog = ctk.CTkInputDialog(text="请输入本地金库主密码\n(用于防范设备物理攻破):", title="安全初始化")
        user_password = dialog.get_input()
        vault_password = user_password if user_password else "default_fallback_password"
        
        self.backup_mgr = BackupManager(p2p_node=self.p2p_node, vault_password=vault_password, vault_dir=vault_dir)
        self.recovery_mgr = RecoveryManager(p2p_node=self.p2p_node, vault_password=vault_password, vault_dir=vault_dir)
        
        self.app_router.register_handler(AppCmd.SHARE_PUSH, self.backup_mgr.handle_incoming_share)
        self.app_router.register_handler(AppCmd.PULL_REQ, self.recovery_mgr.handle_pull_request)
        self.app_router.register_handler(AppCmd.PULL_RESP, self.recovery_mgr.handle_pull_response)
        
        # 添加 ERROR 消息处理器
        def handle_error(peer_addr, msg):
            print(f"[AppRouter] 收到来自 {peer_addr} 的错误消息: {msg.error_msg}")
            if hasattr(self, 'lbl_recovery_status'):
                self.ui_bridge.safe_update_net_status(f"错误: {msg.error_msg}", "#C8504B")
        self.app_router.register_handler(AppCmd.ERROR, handle_error)
        
        self.recovery_mgr.on_progress_update = self._on_recovery_progress
        self.recovery_mgr.on_recovery_success = self._on_recovery_success
        self.recovery_mgr.on_recovery_failed = self._on_recovery_failed

    def _on_recovery_progress(self, file_hash, current, total):
        if hasattr(self, 'recovery_progress'):
            self.ui_bridge.safe_update_progress(current, total)
        if hasattr(self, 'lbl_recovery_status'):
            self.ui_bridge.run_in_main_thread(
                self.lbl_recovery_status.configure,
                text=f"收集份额: {current}/{total}",
                text_color="#E5A50A"
            )

    def _on_recovery_success(self, file_hash, restored_path):
        self.ui_bridge.safe_show_info("成功", f"资产已抗量子重构至:\n{restored_path}")
        self.ui_bridge.safe_update_net_status("资产恢复完成", "#2FA572")
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
            
            # 使用 app 中已有的身份，不要重新生成
            self.dil_pk = self.p2p_node.dil_pk
            self.dil_sk = self.p2p_node.static_sk
            
            # 【核心修改】直接调用底层生成极简版指纹邀请码
            self.invite_code = self.p2p_node.generate_invite_code()
            
        except Exception as e:
            messagebox.showerror("密码学引擎错误", f"无法生成抗量子密钥: {e}")
            self.kyber_pk = b""
            self.dil_pk = b""
            self.invite_code = "QSP-Invite://error"

    def update_status(self, message: str, color: str = "gray"):
        self.status_label.configure(text=f"状态: {message}", text_color=color)

    def clear_main_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def show_net_tab(self):
        self.clear_main_frame()
        
        ctk.CTkLabel(
            self.main_frame, 
            text="本机专属邀请码 (包含公钥指纹与坐标):", 
            font=ctk.CTkFont(size=14)
        ).pack(pady=(40, 10))
        
        self.entry_my_code = ctk.CTkEntry(self.main_frame, width=600)
        self.entry_my_code.insert(0, self.invite_code)
        self.entry_my_code.configure(state='readonly')
        self.entry_my_code.pack(pady=10)
        
        ctk.CTkButton(
            self.main_frame, 
            text="复制邀请码", 
            command=self.copy_code
        ).pack(pady=10)
        
        ctk.CTkLabel(
            self.main_frame, 
            text="连接远端节点 (粘贴邀请码):", 
            font=ctk.CTkFont(size=14)
        ).pack(pady=(40, 10))
        
        self.entry_target_code = ctk.CTkEntry(self.main_frame, width=600)
        self.entry_target_code.pack(pady=10)
        
        ctk.CTkButton(
            self.main_frame, 
            text="发起UDP穿透与安全握手", 
            fg_color="#2FA572", 
            hover_color="#106A43",
            command=self.connect_peer
        ).pack(pady=20)
        
        self.lbl_net_status = ctk.CTkLabel(
            self.main_frame, 
            text="网络状态: 监听端口 8888",
            text_color="gray"
        )
        self.lbl_net_status.pack(pady=20)
        
        self.lbl_peer_list = ctk.CTkLabel(
            self.main_frame,
            text="已连接节点: 0",
            text_color="gray"
        )
        self.lbl_peer_list.pack(pady=10)

    def show_backup_tab(self):
        self.clear_main_frame()
        
        ctk.CTkButton(
            self.main_frame, 
            text="选择待保护机密文件", 
            command=self.select_file
        ).pack(pady=(50, 20))
        
        self.lbl_file = ctk.CTkLabel(
            self.main_frame, 
            text="未选择文件", 
            text_color="gray"
        )
        self.lbl_file.pack(pady=10)
        
        param_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        param_frame.pack(pady=30)
        
        ctk.CTkLabel(param_frame, text="总节点数 (N):").grid(row=0, column=0, padx=10)
        self.entry_n = ctk.CTkEntry(param_frame, width=60)
        self.entry_n.insert(0, "5")
        self.entry_n.grid(row=0, column=1, padx=10)
        
        ctk.CTkLabel(param_frame, text="恢复门限 (T):").grid(row=0, column=2, padx=10)
        self.entry_t = ctk.CTkEntry(param_frame, width=60)
        self.entry_t.insert(0, "3")
        self.entry_t.grid(row=0, column=3, padx=10)
        
        self.btn_execute_backup = ctk.CTkButton(
            self.main_frame, 
            text="执行核心资产分割与加密", 
            fg_color="#C8504B", 
            hover_color="#8E3532",
            command=self.execute_backup
        )
        self.btn_execute_backup.pack(pady=40)
        
        self.backup_progress = ctk.CTkProgressBar(self.main_frame, width=400)
        self.backup_progress.set(0)
        self.backup_progress.pack(pady=20)
        
        self.lbl_backup_status = ctk.CTkLabel(
            self.main_frame,
            text="等待操作...",
            text_color="gray"
        )
        self.lbl_backup_status.pack(pady=10)
        
        self.ui_bridge.bind_widgets(
            lbl_net_status=self.lbl_net_status,
            progress_bar=self.backup_progress,
            btn_backup=self.btn_execute_backup,
            btn_recovery=None
        )

    def show_recovery_tab(self):
        self.clear_main_frame()
        
        ctk.CTkButton(
            self.main_frame, 
            text="导入资产清单 (Manifest)", 
            command=self.load_manifest
        ).pack(pady=(50, 20))
        
        self.lbl_manifest = ctk.CTkLabel(
            self.main_frame, 
            text="未加载清单文件", 
            text_color="gray"
        )
        self.lbl_manifest.pack(pady=10)
        
        self.recovery_progress = ctk.CTkProgressBar(self.main_frame, width=400)
        self.recovery_progress.set(0)
        self.recovery_progress.pack(pady=40)
        
        self.btn_execute_recovery = ctk.CTkButton(
            self.main_frame, 
            text="执行身份签名验证与资产重构", 
            fg_color="#2FA572", 
            hover_color="#106A43",
            command=self.execute_recovery
        )
        self.btn_execute_recovery.pack(pady=20)
        
        self.lbl_recovery_status = ctk.CTkLabel(
            self.main_frame,
            text="等待操作...",
            text_color="gray"
        )
        self.lbl_recovery_status.pack(pady=10)
        
        self.ui_bridge.bind_widgets(
            lbl_net_status=self.lbl_net_status,
            progress_bar=self.recovery_progress,
            btn_backup=None,
            btn_recovery=self.btn_execute_recovery
        )

    def copy_code(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.entry_my_code.get())
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
                # 【核心修改】移除了报错的 target_peer_pk 提取逻辑
                self.p2p_node.static_sk = self.dil_sk
                self.p2p_node._is_initiator = True
                
                # 底层的 connect_via_invite 会自动提取指纹(fp)并启动打洞
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
        
        self.update_status("正在执行资产备份与网络分发...", "#E5A50A")
        self.lbl_backup_status.configure(text="正在启动备份管理器...", text_color="#E5A50A")
        self.backup_progress.set(0.2)
        self.ui_bridge.safe_set_action_buttons_state("disabled")
        
        def do_backup():
            try:
                manifest_path = self.backup_mgr.execute_backup(filepath, n, t)
                
                self.ui_bridge.safe_update_progress(1.0, 1.0)
                self.ui_bridge.run_in_main_thread(self.update_status, "资产备份完成", "#2FA572")
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
                self.ui_bridge.safe_show_error("备份失败", f"处理或分发资产时发生错误: {e}")
            finally:
                self.ui_bridge.safe_set_action_buttons_state("normal")
        
        threading.Thread(target=do_backup, daemon=True).start()

    def load_manifest(self):
        path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        if path:
            self.manifest_path = path
            filename = os.path.basename(path)
            self.lbl_manifest.configure(text=filename)

    def execute_recovery(self):
        manifest_path = getattr(self, 'manifest_path', None)
        if not manifest_path or not os.path.exists(manifest_path):
            messagebox.showerror("错误", "请先加载有效的清单文件！")
            return
        
        self.update_status("正在执行资产恢复与网络寻呼...", "#E5A50A")
        self.lbl_recovery_status.configure(text="正在向 P2P 网络广播拉取请求...", text_color="#E5A50A")
        self.recovery_progress.set(0.1)
        self.ui_bridge.safe_set_action_buttons_state("disabled")
        
        def do_recovery():
            try:
                self.recovery_mgr.execute_recovery(manifest_path)
            except Exception as e:
                self.ui_bridge.run_in_main_thread(
                    self.lbl_recovery_status.configure, text=f"启动错误: {str(e)}", text_color="#C8504B"
                )
                self.ui_bridge.run_in_main_thread(self.update_status, "恢复启动失败", "#C8504B")
                self.ui_bridge.safe_show_error("恢复阻断", f"无法启动资产重构: {e}")
                self.ui_bridge.safe_set_action_buttons_state("normal")
        
        threading.Thread(target=do_recovery, daemon=True).start()
