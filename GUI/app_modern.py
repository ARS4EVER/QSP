# -*- coding: utf-8 -*-
"""
QSP 抗量子资产托管系统 - 现代化 GUI (v2.1 No-Stego)
修改说明：移除图像隐写逻辑，适配纯文件加密存储架构
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import sys
import threading
import json
import hashlib
import uuid
import numpy as np
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
    # [移除] DCTExtractor
    from src.crypto_lattice.signer import LatticeSigner
    from src.secret_sharing.reconstructor import ImageCRTReconstructor
    from src.crypto_lattice.encryptor import LatticeEncryptor
except ImportError as e:
    print(f"核心模块导入失败: {e}")

# --- 全局主题设置 ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ModernApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # 1. 窗口基础设置
        self.title("QSP 抗量子资产托管系统 (PQC Core)")
        self.geometry("1200x800")
        
        # 状态变量
        self.active_identity = None  
        self.loaded_manifest = None  
        self.authorized_shares = []  
        
        # 2. 布局容器
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 3. 创建标签页
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
    # Tab 1: 身份管理 (保持不变)
    # =========================================================================
    def setup_identity_tab(self):
        # ... (此处代码与原版相同，无需修改，为了节省篇幅省略) ...
        frame = self.tab_identity
        frame.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(frame, text="数字身份库 (Identity Vault)", font=("Roboto", 24, "bold")).grid(row=0, column=0, pady=20)
        action_frame = ctk.CTkFrame(frame)
        action_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        self.entry_id_name = ctk.CTkEntry(action_frame, placeholder_text="输入新身份别名 (例如: bob)", width=300)
        self.entry_id_name.pack(side="left", padx=10, pady=10)
        
        ctk.CTkButton(action_frame, text="✨ 铸造新身份", command=self.mint_identity, fg_color="#2CC985").pack(side="left", padx=10)
        ctk.CTkButton(action_frame, text="🔄 刷新列表", command=self.refresh_identity_list, fg_color="transparent", border_width=1).pack(side="left", padx=10)

        self.scroll_identities = ctk.CTkScrollableFrame(frame, label_text="本地可用私钥")
        self.scroll_identities.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        frame.grid_rowconfigure(2, weight=1)
        self.refresh_identity_list()

    def mint_identity(self):
        name = self.entry_id_name.get().strip()
        if not name: return
        try:
            pk, sk = KeyTool.generate_keypair()
            save_dir = Config.KEYS_DIR # 使用配置中的路径
            os.makedirs(save_dir, exist_ok=True)
            with open(os.path.join(save_dir, f"{name}.sk"), 'w') as f: json.dump(sk, f, indent=4)
            with open(os.path.join(save_dir, f"{name}.pk"), 'w') as f: json.dump(pk, f, indent=4)
            messagebox.showinfo("成功", f"身份 [{name}] 铸造完成！")
            self.refresh_identity_list()
        except Exception as e: messagebox.showerror("错误", str(e))

    def refresh_identity_list(self):
        for widget in self.scroll_identities.winfo_children(): widget.destroy()
        key_dir = Config.KEYS_DIR
        if not os.path.exists(key_dir): os.makedirs(key_dir)
        files = [f for f in os.listdir(key_dir) if f.endswith('.sk')]
        for f in files:
            row = ctk.CTkFrame(self.scroll_identities)
            row.pack(fill="x", pady=5)
            icon = "🔑" if f == self.active_identity else "📄"
            ctk.CTkLabel(row, text=f"{icon} {f}", font=("Consolas", 14)).pack(side="left", padx=10)
            if f != self.active_identity:
                ctk.CTkButton(row, text="设为活跃", width=80, command=lambda fname=f: self.set_active_identity(fname)).pack(side="right", padx=10)
            else:
                ctk.CTkButton(row, text="取消活跃", width=80, command=self.unset_active_identity).pack(side="right", padx=10)

    def set_active_identity(self, filename):
        self.active_identity = filename
        self.refresh_identity_list()
        self.update_user_status()

    def unset_active_identity(self):
        self.active_identity = None
        self.refresh_identity_list()
        self.update_user_status()

    # =========================================================================
    # Tab 2: 资产锁定 (Dealer Hub) - [关键修改]
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
        
        # [修改] 移除了选择载体目录的步骤
        # ctk.CTkLabel(config_panel, text="第二步: 选择载体库").pack(pady=(20,5))
        # self.btn_covers = ...
        
        ctk.CTkLabel(config_panel, text="第二步: 接收者公钥").pack(pady=(20,5))
        self.btn_pk = ctk.CTkButton(config_panel, text="📂 选择公钥目录", command=self.load_pk_dir)
        self.btn_pk.pack(pady=5)
        
        ctk.CTkLabel(config_panel, text="第三步: 分发目录").pack(pady=(20,5))
        self.btn_output = ctk.CTkButton(config_panel, text="📂 选择输出目录", command=self.load_output_dir)
        self.btn_output.pack(pady=5)
        
        ctk.CTkLabel(config_panel, text="第四步: 设置份额数量 (n)").pack(pady=(20,5))
        self.slider_n = ctk.CTkSlider(config_panel, from_=3, to=10, number_of_steps=7)
        self.slider_n.set(5)
        self.slider_n.pack(pady=5)
        self.lbl_n = ctk.CTkLabel(config_panel, text="n = 5")
        self.lbl_n.pack()
        self.slider_n.configure(command=lambda v: self.lbl_n.configure(text=f"n = {int(v)}"))
        
        ctk.CTkLabel(config_panel, text="第五步: 设置门限 (t)").pack(pady=(20,5))
        self.slider_t = ctk.CTkSlider(config_panel, from_=2, to=5, number_of_steps=3)
        self.slider_t.set(3)
        self.slider_t.pack(pady=5)
        self.lbl_t = ctk.CTkLabel(config_panel, text="t = 3")
        self.lbl_t.pack()
        self.slider_t.configure(command=lambda v: self.lbl_t.configure(text=f"t = {int(v)}"))

        ctk.CTkButton(config_panel, text="🔒 执行锁定 (Lock)", fg_color="#E04F5F", height=40,
                     command=self.run_locking_process).pack(pady=(30, 10), fill="x", padx=10)

        # 右侧：日志
        self.dealer_log = ctk.CTkTextbox(frame, width=400)
        self.dealer_log.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        self.secret_path = None
        # self.covers_dir = None # 移除
        self.pk_dir = os.path.abspath(Config.KEYS_DIR)
        self.output_dir = os.path.abspath(Config.SHARES_DIR)

    def load_secret_img(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg")])
        if path:
            self.secret_path = path
            self.btn_secret.configure(text=f"✅ {os.path.basename(path)}")
            
    def load_pk_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.pk_dir = path
            pk_files = [f for f in os.listdir(path) if f.endswith('.pk')]
            n = len(pk_files)
            self.btn_pk.configure(text=f"✅ {os.path.basename(path)} (n={n})")
            
    def load_output_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.output_dir = path
            self.btn_output.configure(text=f"✅ {os.path.basename(path)}")

    def run_locking_process(self):
        if not self.secret_path:
            messagebox.showerror("错误", "请先选择秘密图像")
            return
            
        n = int(self.slider_n.get())
        t = int(self.slider_t.get())
        if t >= n:
            messagebox.showerror("错误", "门限(t)必须小于份额数量(n)")
            return
        
        def task():
            self.log(self.dealer_log, ">>> 启动资产锁定流程 (PQC Only)...")
            try:
                locker = AssetLocker()
                # [修改] 调用更新后的接口，移除了 cover_dir
                locker.lock_and_distribute(
                    secret_img_path=self.secret_path,
                    pk_dir=self.pk_dir,
                    output_dir=self.output_dir,
                    n=n,
                    t=t
                )
                self.log(self.dealer_log, "✅ 锁定成功！加密分片已生成。")
                self.log(self.dealer_log, "请前往 'User' 标签页进行恢复。")
            except Exception as e:
                self.log(self.dealer_log, f"❌ 失败: {str(e)}")
        
        threading.Thread(target=task).start()

    # =========================================================================
    # Tab 3: 授权与恢复 (User Center) - [关键修改]
    # =========================================================================
    def setup_user_tab(self):
        # ... (布局代码基本不变，省略部分重复代码) ...
        frame = self.tab_user
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        status_bar = ctk.CTkFrame(frame, height=40)
        status_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        self.lbl_user_status = ctk.CTkLabel(status_bar, text="当前身份: 未选择", font=("Roboto", 14))
        self.lbl_user_status.pack(side="left", padx=10)
        ctk.CTkButton(status_bar, text="📂 加载资产清单 (Manifest)", command=self.load_manifest_file).pack(side="right", padx=10, pady=5)

        config_bar = ctk.CTkFrame(frame, height=80)
        config_bar.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        
        # 简化：仅显示加载路径配置
        self.entry_assets = ctk.CTkEntry(config_bar, width=300)
        self.entry_assets.pack(side="left", padx=10, pady=10)
        self.entry_assets.insert(0, os.path.abspath(Config.SHARES_DIR))
        
        self.scroll_shares = ctk.CTkScrollableFrame(frame, label_text="待授权加密分片 (Encrypted Shares)")
        self.scroll_shares.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

        recover_panel = ctk.CTkFrame(frame, height=120)
        recover_panel.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        
        self.lbl_progress = ctk.CTkLabel(recover_panel, text="收集进度: 0 / 0")
        self.lbl_progress.pack(pady=2)
        
        self.btn_reconstruct = ctk.CTkButton(recover_panel, text="🚀 启动重构 (Reconstruct)", 
                                           state="disabled", fg_color="gray", command=self.run_reconstruction)
        self.btn_reconstruct.pack(pady=5)

    def update_user_status(self):
        if self.active_identity:
            self.lbl_user_status.configure(text=f"当前身份: 👤 {self.active_identity}", text_color="#2CC985")
            if self.loaded_manifest: self.refresh_share_list()
        else:
            self.lbl_user_status.configure(text="当前身份: ⚠️ 未选择", text_color="orange")

    def load_manifest_file(self):
        path = filedialog.askopenfilename(initialdir=self.entry_assets.get(), filetypes=[("JSON", "*.json")])
        if not path: return
        try:
            with open(path, 'r') as f: self.loaded_manifest = json.load(f)
            self.authorized_shares = []
            self.refresh_share_list()
            n, t = self.loaded_manifest['total_shares'], self.loaded_manifest['threshold']
            messagebox.showinfo("加载成功", f"发现 {n} 个加密分片 (t={t})")
        except Exception as e: messagebox.showerror("错误", f"清单解析失败: {e}")

    def refresh_share_list(self):
        for widget in self.scroll_shares.winfo_children(): widget.destroy()
        if not self.loaded_manifest: return
        t = self.loaded_manifest['threshold']
        count = len(self.authorized_shares)
        self.lbl_progress.configure(text=f"收集进度: {count} / {t}")
        if count >= t: self.btn_reconstruct.configure(state="normal", fg_color="#2CC985")
        
        for entry in self.loaded_manifest['registry']:
            self.create_share_item(entry)

    def create_share_item(self, entry):
        card = ctk.CTkFrame(self.scroll_shares)
        card.pack(fill="x", pady=5, padx=5)
        
        # [修改] 显示文件路径而不是 carrier_file
        # entry 现在包含 'file_path'
        file_name = os.path.basename(entry.get('file_path', entry.get('carrier_file', 'unknown')))
        info_text = f"📄 {file_name}\n归属人: {entry['owner_alias']}"
        ctk.CTkLabel(card, text=info_text, justify="left", font=("Arial", 12)).pack(side="left", padx=10)
        
        is_authorized = any(s['idx'] == entry['share_index'] for s in self.authorized_shares)
        if is_authorized:
            ctk.CTkLabel(card, text="✅ 已解密", text_color="#2CC985").pack(side="right", padx=20)
        else:
            is_owner = False
            if self.active_identity:
                active_alias = self.active_identity.replace('.sk', '')
                is_owner = (entry['owner_alias'] == active_alias)
            
            if is_owner:
                btn = ctk.CTkButton(card, text="🔓 解密并授权", width=120, command=lambda e=entry: self.authorize_share(e))
                btn.pack(side="right", padx=10)
            else:
                status = "需登录身份" if not self.active_identity else "无权操作"
                ctk.CTkLabel(card, text=f"🔒 {status}", text_color="gray").pack(side="right", padx=20)

    def _find_share_file(self, rel_path):
        """[修改] 查找加密分片文件 (.dat)"""
        # 尝试 1: 绝对路径拼接
        base_dir = os.path.dirname(self.loaded_manifest.get('_path', self.entry_assets.get()))
        path1 = os.path.join(base_dir, rel_path)
        if os.path.exists(path1): return path1
        
        # 尝试 2: 在当前目录查找
        path2 = os.path.join(self.entry_assets.get(), rel_path)
        if os.path.exists(path2): return path2
        
        return None

    def authorize_share(self, entry):
        """[修改] 移除隐写提取，直接读取文件解密"""
        if not self.active_identity: return

        confirm = messagebox.askyesno("授权确认", f"是否使用身份 [{self.active_identity}] 解密此分片？")
        if not confirm: return

        try:
            sk_path = os.path.join(Config.KEYS_DIR, self.active_identity)
            with open(sk_path, 'r') as f: sk = json.load(f)
            
            # 1. 查找文件
            file_rel_path = entry.get('file_path', entry.get('carrier_file')) # 兼容旧字段
            file_path = self._find_share_file(file_rel_path)
            
            if not file_path:
                # 尝试手动选择
                file_path = filedialog.askopenfilename(title=f"请找到文件 {os.path.basename(file_rel_path)}")
                if not file_path: return

            # 2. 直接读取加密数据 (不再需要 DCTExtractor)
            with open(file_path, 'rb') as f:
                encrypted_bytes = f.read()
            
            # 3. PQC 解密
            raw_share_bytes = LatticeEncryptor.decrypt_data(sk, encrypted_bytes)
            if raw_share_bytes is None:
                raise ValueError("解密失败！私钥错误或数据损坏。")
            
            # 4. 哈希校验
            current_hash = hashlib.sha256(raw_share_bytes).hexdigest()
            if current_hash != entry['share_fingerprint']:
                raise ValueError("完整性校验失败！(Hash Mismatch)")
            
            # 5. 反序列化
            reconstructor = ImageCRTReconstructor()
            payload = reconstructor.deserialize_share(raw_share_bytes)
            if not payload: raise ValueError("分片数据格式错误")
            
            self.authorized_shares.append(payload)
            messagebox.showinfo("成功", "解密授权成功！")
            self.refresh_share_list()
                
        except Exception as e:
            messagebox.showerror("授权失败", str(e))

    def run_reconstruction(self):
        if not self.authorized_shares: return
        try:
            reconstructor = ImageCRTReconstructor()
            img_arr = reconstructor.reconstruct(self.authorized_shares)
            
            save_path = os.path.join(Config.RESTORED_DIR, "recovered_secret_final.png")
            Image.fromarray(img_arr).save(save_path)
            
            messagebox.showinfo("重构成功", f"秘密图像已恢复至:\n{save_path}")
            os.startfile(os.path.dirname(save_path))
            
        except Exception as e:
            messagebox.showerror("重构失败", str(e))

    def log(self, widget, msg):
        widget.insert("end", f"{msg}\n")
        widget.see("end")

if __name__ == "__main__":
    app = ModernApp()
    app.mainloop()