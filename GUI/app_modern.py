# -*- coding: utf-8 -*-
"""
QSP 抗量子资产托管系统 - 现代化 GUI (v2.0)
集成：身份管理 + Dealer锁定 + 交互式多方授权恢复
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import sys
import threading
import json
import hashlib
import time
import uuid
from PIL import Image

# --- 路径配置 ---
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

# --- 核心模块导入 ---
try:
    from src.config import Config
    from src.crypto_lattice.keygen import KeyTool
    from src.dealer.locker import AssetLocker
    from src.image_stego.dct_extract import DCTExtractor
    from src.crypto_lattice.signer import LatticeSigner
    from src.secret_sharing.reconstructor import ImageCRTReconstructor
    from src.crypto_lattice.encryptor import LatticeEncryptor
except ImportError as e:
    print(f"核心模块导入失败: {e}")
    # 仅用于无后端测试，生产环境请删除
    class Config: PATHS = {"keys": "data/keys", "shares": "data/shares"}

# --- 全局主题设置 ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ModernApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # 1. 窗口基础设置
        self.title("QSP 抗量子资产托管系统 (Zero Trust & Interactive Auth)")
        self.geometry("1200x800")
        
        # 状态变量
        self.active_identity = None  # 当前选中的身份 (文件名, 如 alice.sk)
        self.loaded_manifest = None  # 当前加载的资产清单
        self.authorized_shares = []  # 已授权的份额缓存
        
        # 2. 布局容器
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 3. 创建标签页组件 (核心架构)
        self.tabview = ctk.CTkTabview(self, width=1100, height=750)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        self.tab_identity = self.tabview.add("🪪 身份管理")
        self.tab_dealer = self.tabview.add("🔒 资产锁定 (Dealer)")
        self.tab_user = self.tabview.add("🔓 授权与恢复 (User)")

        # 4. 初始化各模块
        self.setup_identity_tab()
        self.setup_dealer_tab()
        self.setup_user_tab()

    # =========================================================================
    # Tab 1: 身份管理 (Identity Manager)
    # =========================================================================
    def setup_identity_tab(self):
        frame = self.tab_identity
        frame.grid_columnconfigure(0, weight=1)

        # 标题区
        ctk.CTkLabel(frame, text="数字身份库 (Identity Vault)", font=("Roboto", 24, "bold")).grid(row=0, column=0, pady=20)
        
        # 操作区
        action_frame = ctk.CTkFrame(frame)
        action_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        self.entry_id_name = ctk.CTkEntry(action_frame, placeholder_text="输入新身份别名 (例如: bob)", width=300)
        self.entry_id_name.pack(side="left", padx=10, pady=10)
        
        ctk.CTkButton(action_frame, text="✨ 铸造新身份", command=self.mint_identity, fg_color="#2CC985").pack(side="left", padx=10)
        ctk.CTkButton(action_frame, text="🔄 刷新列表", command=self.refresh_identity_list, fg_color="transparent", border_width=1).pack(side="left", padx=10)

        # 列表显示区
        self.scroll_identities = ctk.CTkScrollableFrame(frame, label_text="本地可用私钥")
        self.scroll_identities.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        frame.grid_rowconfigure(2, weight=1)

        # 初始刷新
        self.refresh_identity_list()

    def mint_identity(self):
        name = self.entry_id_name.get().strip()
        if not name:
            messagebox.showwarning("提示", "请输入身份别名")
            return
        
        try:
            # 调用后端生成
            pk, sk = KeyTool.generate_keypair()
            
            # 保存逻辑
            save_dir = "my_identities"
            os.makedirs(save_dir, exist_ok=True)
            
            with open(os.path.join(save_dir, f"{name}.sk"), 'w') as f:
                json.dump(sk, f, indent=4)
            with open(os.path.join(save_dir, f"{name}.pk"), 'w') as f:
                json.dump(pk, f, indent=4)
                
            messagebox.showinfo("成功", f"身份 [{name}] 铸造完成！\n私钥已安全存储。")
            self.refresh_identity_list()
            
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def refresh_identity_list(self):
        # 清空列表
        for widget in self.scroll_identities.winfo_children():
            widget.destroy()
            
        key_dir = "my_identities"
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
            
        files = [f for f in os.listdir(key_dir) if f.endswith('.sk')]
        
        for f in files:
            row = ctk.CTkFrame(self.scroll_identities)
            row.pack(fill="x", pady=5)
            
            icon = "🔑" if f == self.active_identity else "📄"
            color = "#2CC985" if f == self.active_identity else "transparent"
            
            ctk.CTkLabel(row, text=f"{icon} {f}", font=("Consolas", 14)).pack(side="left", padx=10)
            
            # 切换身份按钮
            if f != self.active_identity:
                ctk.CTkButton(row, text="设为活跃", width=80, 
                             command=lambda fname=f: self.set_active_identity(fname)).pack(side="right", padx=10)
            else:
                ctk.CTkLabel(row, text="[当前活跃]", text_color="#2CC985").pack(side="right", padx=10)

    def set_active_identity(self, filename):
        self.active_identity = filename
        self.refresh_identity_list()
        self.update_user_status() # 更新 User Tab 的状态

    # =========================================================================
    # Tab 2: 资产锁定 (Dealer Hub)
    # =========================================================================
    def setup_dealer_tab(self):
        frame = self.tab_dealer
        frame.grid_columnconfigure(1, weight=1)

        # 左侧：配置区
        config_panel = ctk.CTkFrame(frame)
        config_panel.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        ctk.CTkLabel(config_panel, text="第一步: 选择秘密图像").pack(pady=5)
        self.btn_secret = ctk.CTkButton(config_panel, text="📂 加载秘密图", command=self.load_secret_img)
        self.btn_secret.pack(pady=5)
        
        ctk.CTkLabel(config_panel, text="第二步: 选择载体库").pack(pady=(20,5))
        self.btn_covers = ctk.CTkButton(config_panel, text="📂 选择载体目录", command=self.load_covers_dir)
        self.btn_covers.pack(pady=5)
        
        ctk.CTkLabel(config_panel, text="第三步: 接收者公钥").pack(pady=(20,5))
        self.btn_pk = ctk.CTkButton(config_panel, text="📂 选择公钥目录", command=self.load_pk_dir)
        self.btn_pk.pack(pady=5)
        
        ctk.CTkLabel(config_panel, text="第四步: 分发目录").pack(pady=(20,5))
        self.btn_output = ctk.CTkButton(config_panel, text="📂 选择输出目录", command=self.load_output_dir)
        self.btn_output.pack(pady=5)
        
        ctk.CTkLabel(config_panel, text="第五步: 设置份额数量 (n)").pack(pady=(20,5))
        self.slider_n = ctk.CTkSlider(config_panel, from_=3, to=10, number_of_steps=7)
        self.slider_n.set(5)
        self.slider_n.pack(pady=5)
        self.lbl_n = ctk.CTkLabel(config_panel, text="n = 5")
        self.lbl_n.pack()
        self.slider_n.configure(command=lambda v: self.lbl_n.configure(text=f"n = {int(v)}"))
        
        ctk.CTkLabel(config_panel, text="第六步: 设置门限 (t)").pack(pady=(20,5))
        self.slider_t = ctk.CTkSlider(config_panel, from_=2, to=5, number_of_steps=3)
        self.slider_t.set(3)
        self.slider_t.pack(pady=5)
        self.lbl_t = ctk.CTkLabel(config_panel, text="t = 3")
        self.lbl_t.pack()
        self.slider_t.configure(command=lambda v: self.lbl_t.configure(text=f"t = {int(v)}"))

        ctk.CTkButton(config_panel, text="🔒 执行锁定 (Lock)", fg_color="#E04F5F", height=40,
                     command=self.run_locking_process).pack(pady=(30, 10), fill="x", padx=10)

        # 右侧：日志与预览
        self.dealer_log = ctk.CTkTextbox(frame, width=400)
        self.dealer_log.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        self.secret_path = None
        self.covers_dir = None
        self.pk_dir = os.path.abspath("my_identities")
        self.output_dir = os.path.abspath("distributed_assets")

    def load_secret_img(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg")])
        if path:
            self.secret_path = path
            self.btn_secret.configure(text=f"✅ {os.path.basename(path)}")
            
    def load_covers_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.covers_dir = path
            self.btn_covers.configure(text=f"✅ {os.path.basename(path)}")
            
    def load_pk_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.pk_dir = path
            # 检测公钥数量
            pk_files = [f for f in os.listdir(path) if f.endswith('.pk')]
            n = len(pk_files)
            self.btn_pk.configure(text=f"✅ {os.path.basename(path)} (n={n})")
            
    def load_output_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.output_dir = path
            self.btn_output.configure(text=f"✅ {os.path.basename(path)}")

    def run_locking_process(self):
        if not (self.secret_path and self.covers_dir):
            messagebox.showerror("错误", "请先选择秘密图像和载体目录")
            return
            
        n = int(self.slider_n.get())
        t = int(self.slider_t.get())
        
        if t >= n:
            messagebox.showerror("错误", "门限(t)必须小于份额数量(n)")
            return
        
        def task():
            self.log(self.dealer_log, ">>> 启动资产锁定流程...")
            try:
                locker = AssetLocker()
                locker.lock_and_distribute(
                    secret_img_path=self.secret_path,
                    pk_dir=self.pk_dir,
                    cover_dir=self.covers_dir,
                    output_dir=self.output_dir,
                    n=n,
                    t=t
                )
                self.log(self.dealer_log, "✅ 锁定成功！资产清单已生成。")
                self.log(self.dealer_log, "请前往 'User' 标签页进行恢复。")
            except Exception as e:
                self.log(self.dealer_log, f"❌ 失败: {str(e)}")
        
        threading.Thread(target=task).start()

    # =========================================================================
    # Tab 3: 授权与恢复 (User Center) - 核心交互区
    # =========================================================================
    def setup_user_tab(self):
        frame = self.tab_user
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # 顶部状态栏
        status_bar = ctk.CTkFrame(frame, height=40)
        status_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        
        self.lbl_user_status = ctk.CTkLabel(status_bar, text="当前身份: 未选择", font=("Roboto", 14))
        self.lbl_user_status.pack(side="left", padx=10)
        
        ctk.CTkButton(status_bar, text="📂 加载资产清单 (Manifest)", command=self.load_manifest_file).pack(side="right", padx=10, pady=5)

        # 配置区
        config_bar = ctk.CTkFrame(frame, height=60)
        config_bar.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        
        ctk.CTkLabel(config_bar, text="资产位置:").pack(side="left", padx=10, pady=5)
        self.entry_assets = ctk.CTkEntry(config_bar, width=200)
        self.entry_assets.pack(side="left", padx=5, pady=5)
        self.entry_assets.insert(0, os.path.abspath("distributed_assets"))
        
        ctk.CTkLabel(config_bar, text="私钥库:").pack(side="left", padx=10, pady=5)
        self.entry_keys = ctk.CTkEntry(config_bar, width=200)
        self.entry_keys.pack(side="left", padx=5, pady=5)
        self.entry_keys.insert(0, os.path.abspath("my_identities"))

        # 中部：交互式授权列表
        self.scroll_shares = ctk.CTkScrollableFrame(frame, label_text="待授权资产碎片 (Interactive Auth)")
        self.scroll_shares.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

        # 底部：恢复控制区
        recover_panel = ctk.CTkFrame(frame, height=120)
        recover_panel.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        
        self.progress_bar = ctk.CTkProgressBar(recover_panel)
        self.progress_bar.pack(fill="x", padx=20, pady=5)
        self.progress_bar.set(0)
        
        self.lbl_progress = ctk.CTkLabel(recover_panel, text="收集进度: 0 / 0")
        self.lbl_progress.pack(pady=2)
        
        # 签名操作按钮
        button_frame = ctk.CTkFrame(recover_panel)
        button_frame.pack(fill="x", padx=20, pady=5)
        
        self.btn_export_signature = ctk.CTkButton(button_frame, text="📤 导出签名文件", command=self.export_signature)
        self.btn_export_signature.pack(side="left", padx=10)
        
        self.btn_import_signature = ctk.CTkButton(button_frame, text="📥 导入签名文件", command=self.import_signature)
        self.btn_import_signature.pack(side="left", padx=10)
        
        self.btn_reconstruct = ctk.CTkButton(recover_panel, text="🚀 启动重构 (Reconstruct)", 
                                           state="disabled", fg_color="gray", command=self.run_reconstruction)
        self.btn_reconstruct.pack(pady=5)

    def update_user_status(self):
        if self.active_identity:
            self.lbl_user_status.configure(text=f"当前身份: 👤 {self.active_identity}", text_color="#2CC985")
            # 刷新列表状态（如果有清单）
            if self.loaded_manifest:
                self.refresh_share_list()
        else:
            self.lbl_user_status.configure(text="当前身份: ⚠️ 未选择 (请去身份标签页选择)", text_color="orange")

    def load_manifest_file(self):
        path = filedialog.askopenfilename(initialdir=self.entry_assets.get(), filetypes=[("JSON", "*.json")])
        if not path:
            return
            
        try:
            with open(path, 'r') as f:
                self.loaded_manifest = json.load(f)
            
            # 初始化状态
            self.authorized_shares = []
            self.refresh_share_list()
            n = self.loaded_manifest['total_shares']
            t = self.loaded_manifest['threshold']
            messagebox.showinfo("加载成功", f"发现 {n} 个资产碎片 (n={n})。\n恢复门限: {t} (t={t})")
            
        except Exception as e:
            messagebox.showerror("错误", f"清单解析失败: {e}")

    def refresh_share_list(self):
        # 清空旧列表
        for widget in self.scroll_shares.winfo_children():
            widget.destroy()
            
        if not self.loaded_manifest:
            return

        t = self.loaded_manifest['threshold']
        n = self.loaded_manifest['total_shares']
        current_auth_count = len(self.authorized_shares)
        
        # 更新进度条
        self.lbl_progress.configure(text=f"收集进度: {current_auth_count} / {t} (共 {n} 个份额)")
        self.progress_bar.set(min(current_auth_count / t, 1.0))
        
        if current_auth_count >= t:
            self.btn_reconstruct.configure(state="normal", fg_color="#2CC985")
        else:
            self.btn_reconstruct.configure(state="disabled", fg_color="gray")

        # 生成列表项
        for entry in self.loaded_manifest['registry']:
            self.create_share_item(entry)

    def create_share_item(self, entry):
        """创建单个碎片的交互行"""
        card = ctk.CTkFrame(self.scroll_shares)
        card.pack(fill="x", pady=5, padx=5)
        
        # 信息列
        info_text = f"📄 {entry['carrier_file']}\n归属人: {entry['owner_alias']}"
        ctk.CTkLabel(card, text=info_text, justify="left", font=("Arial", 12)).pack(side="left", padx=10)
        
        # 指纹列 (截断显示)
        fingerprint = entry['share_fingerprint'][:8] + "..."
        ctk.CTkLabel(card, text=f"Hash: {fingerprint}", text_color="gray").pack(side="left", padx=10)
        
        # 状态/操作列
        # 判断该碎片是否已被当前会话授权
        is_authorized = any(s['idx'] == entry['share_index'] for s in self.authorized_shares)
        
        if is_authorized:
            ctk.CTkLabel(card, text="✅ 已授权", text_color="#2CC985").pack(side="right", padx=20)
        else:
            # 判断是否有权授权 (Active Identity matches Owner Alias)
            # 处理owner_alias的一致性问题：活跃身份是完整文件名（如alice.sk），而owner_alias是用户别名（如alice）
            is_owner = False
            if self.active_identity:
                # 提取活跃身份的用户别名（去掉.sk后缀）
                active_alias = self.active_identity.replace('.sk', '')
                # 比较用户别名
                is_owner = (entry['owner_alias'] == active_alias)
            
            if is_owner:
                btn = ctk.CTkButton(card, text="✍️ 签名授权", width=100,
                                   command=lambda e=entry: self.authorize_share(e))
                btn.pack(side="right", padx=10)
            else:
                if not self.active_identity:
                    status = "需登录身份"
                else:
                    status = "无权操作"
                ctk.CTkLabel(card, text=f"🔒 {status}", text_color="gray").pack(side="right", padx=20)

    def _find_image_path(self, carrier_file):
        """
        智能路径查找：尝试多种路径策略找到图片文件
        """
        # 尝试 1: 直接拼接 (标准情况)
        path1 = os.path.join(self.entry_assets.get(), carrier_file)
        if os.path.exists(path1):
            return path1
        
        # 尝试 2: 假设图片就在资产目录的根目录
        path2 = os.path.join(self.entry_assets.get(), os.path.basename(carrier_file))
        if os.path.exists(path2):
            return path2
        
        # 尝试 3: 检查资产目录的子目录
        for root, dirs, files in os.walk(self.entry_assets.get()):
            for file in files:
                if file == os.path.basename(carrier_file):
                    return os.path.join(root, file)
        # 尝试 4: 检查dataset/2_shares目录
        dataset_path = os.path.join(project_root, "dataset", "2_shares")
        if os.path.exists(dataset_path):
            # 尝试直接拼接
            path4 = os.path.join(dataset_path, carrier_file)
            if os.path.exists(path4):
                return path4
            
            # 尝试遍历dataset/2_shares目录
            for root, dirs, files in os.walk(dataset_path):
                for file in files:
                    if file == os.path.basename(carrier_file):
                        return os.path.join(root, file)
        
        # 尝试 5: 检查当前工作目录
        cwd = os.getcwd()
        path5 = os.path.join(cwd, carrier_file)
        if os.path.exists(path5):
            return path5
        
        # 尝试 6: 检查项目根目录
        path6 = os.path.join(project_root, carrier_file)
        if os.path.exists(path6):
            return path6
        
        return None

    def authorize_share(self, entry, export_only=False):
        """交互式授权的核心逻辑"""
        if not self.active_identity:
            return

        # 1. 弹出确认框 (模拟硬件钱包确认)
        confirm = messagebox.askyesno(
            "安全警告", 
            f"您正在使用身份 [{self.active_identity}] 对以下资产进行解密和签名：\n\n"
            f"文件: {entry['carrier_file']}\n"
            f"指纹: {entry['share_fingerprint'][:16]}...\n\n"
            "是否确认授权？"
        )
        if not confirm:
            return

        # 2. 执行解密和签名 (调用后端)
        try:
            # 读取私钥
            sk_path = os.path.join(self.entry_keys.get(), self.active_identity)
            with open(sk_path, 'r') as f:
                sk = json.load(f)
            
            # 智能路径查找
            stego_path = self._find_image_path(entry['carrier_file'])
            if not stego_path:
                raise ValueError(f"找不到图片文件: {entry['carrier_file']}\n请确保图片与清单在正确的位置。")
            
            # 读取隐写图片并提取数据
            extractor = DCTExtractor()
            encrypted_bytes = extractor.extract(stego_path)
            
            # 解密数据
            raw_share_bytes = LatticeEncryptor.decrypt_data(sk, encrypted_bytes)
            if raw_share_bytes is None:
                raise ValueError("解密失败！私钥不匹配或数据损坏。")
            
            # 完整性校验
            current_hash = hashlib.sha256(raw_share_bytes).hexdigest()
            if current_hash != entry['share_fingerprint']:
                raise ValueError("数据完整性校验失败！文件可能被篡改。")
            
            # 生成会话ID和签名
            session_id = str(uuid.uuid4())
            msg = (current_hash + session_id).encode()
            signer = LatticeSigner()
            signature = signer.sign(sk, msg)
            
            # 3. 反序列化份额数据
            reconstructor = ImageCRTReconstructor()
            payload = reconstructor.deserialize_share(raw_share_bytes)
            
            if not payload:
                raise ValueError("份额反序列化失败")
            
            if export_only:
                # 导出为签名文件
                signature_data = {
                    "share_index": entry['share_index'],
                    "share_fingerprint": current_hash,
                    "session_id": session_id,
                    "signature": signature,
                    "owner_alias": self.active_identity.replace('.sk', ''),  # 使用去掉 .sk 后缀的用户别名
                    "payload": payload
                }
                
                # 保存签名文件
                export_path = filedialog.asksaveasfilename(
                    defaultextension=".sig",
                    filetypes=[("Signature Files", "*.sig"), ("All Files", "*")],
                    initialfile=f"{self.active_identity.replace('.sk', '')}_signature.sig"
                )
                
                if export_path:
                    with open(export_path, 'w') as f:
                        json.dump(signature_data, f, indent=4)
                    messagebox.showinfo("成功", f"签名文件已导出至: {export_path}")
            else:
                # 将数据存入内存缓存
                self.authorized_shares.append(payload)
                messagebox.showinfo("成功", "解密和签名成功！已将份额加入重构池。")
                self.refresh_share_list()
                
        except Exception as e:
            messagebox.showerror("授权失败", str(e))

    def export_signature(self):
        """导出签名文件，用于分布式模式"""
        if not self.active_identity:
            messagebox.showwarning("提示", "请先设置当前活跃身份")
            return
        
        if not self.loaded_manifest:
            messagebox.showwarning("提示", "请先加载资产清单")
            return
        
        # 查找归属人为当前活跃身份的碎片
        owner_shares = [entry for entry in self.loaded_manifest['registry'] 
                      if entry['owner_alias'] == self.active_identity]
        
        if not owner_shares:
            messagebox.showwarning("提示", f"未找到归属人为 {self.active_identity} 的资产碎片")
            return
        
        # 对第一个归属人为当前活跃身份的碎片执行签名并导出
        self.authorize_share(owner_shares[0], export_only=True)

    def import_signature(self):
        """导入签名文件，用于分布式模式"""
        if not self.loaded_manifest:
            messagebox.showwarning("提示", "请先加载资产清单")
            return
        
        # 打开文件选择对话框，选择签名文件
        import_path = filedialog.askopenfilename(
            filetypes=[("Signature Files", "*.sig"), ("All Files", "*")]
        )
        
        if not import_path:
            return
        
        try:
            # 读取签名文件内容
            with open(import_path, 'r') as f:
                signature_data = json.load(f)
            
            # 验证签名文件的有效性
            if not all(key in signature_data for key in ['payload', 'owner_alias', 'share_fingerprint']):
                raise ValueError("签名文件格式无效")
            
            # 检查该份额是否已经被授权
            share_index = signature_data.get('share_index')
            is_already_authorized = any(s.get('idx') == share_index for s in self.authorized_shares)
            
            if is_already_authorized:
                messagebox.showinfo("提示", "该份额已经被授权，无需重复导入")
                return
            
            # 将签名文件中的payload添加到内存缓存
            self.authorized_shares.append(signature_data['payload'])
            messagebox.showinfo("成功", f"签名文件已导入，所有者: {signature_data['owner_alias']}")
            self.refresh_share_list()
            
        except Exception as e:
            messagebox.showerror("导入失败", str(e))

    def run_reconstruction(self):
        """执行最终重构"""
        if not self.authorized_shares:
            return
            
        try:
            reconstructor = ImageCRTReconstructor()
            img_arr = reconstructor.reconstruct(self.authorized_shares)
            
            # 使用用户配置的资产位置作为保存路径
            save_path = os.path.join(self.entry_assets.get(), "recovered_secret_gui.png")
            Image.fromarray(img_arr).save(save_path)
            
            # 弹窗展示结果
            top = ctk.CTkToplevel(self)
            top.title("🎉 秘密已恢复")
            top.geometry("500x500")
            
            pil_img = Image.open(save_path)
            # 缩放预览
            pil_img.thumbnail((400, 400))
            ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=pil_img.size)
            
            ctk.CTkLabel(top, image=ctk_img, text="").pack(pady=20)
            ctk.CTkButton(top, text="打开文件所在位置", command=lambda: os.startfile(os.path.abspath(save_path))).pack()
            
        except Exception as e:
            messagebox.showerror("重构失败", str(e))

    # --- 通用日志 ---
    def log(self, widget, msg):
        widget.insert("end", f"{msg}\n")
        widget.see("end")

if __name__ == "__main__":
    app = ModernApp()
    app.mainloop()
