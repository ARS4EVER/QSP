# -*- coding: utf-8 -*-

import os
import sys
import json
import base64
import threading
import customtkinter as ctk
from tkinter import messagebox
from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import DATA_DIR, KEYS_DIR
from src.network.p2p_manager import P2PNode
from src.crypto_lattice.wrapper import LatticeWrapper
from src.app.vault_crypto import VaultCrypto, PasswordAuthError


class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("QSP - 本地认证")
        self.geometry("400x320")
        self.eval('tk::PlaceWindow . center')
        self.resizable(False, False)
        
        logo_path = os.path.join(os.path.dirname(__file__), "image", "logo.png")
        if os.path.exists(logo_path):
            try:
                from PIL import Image
                icon_image = Image.open(logo_path)
                self.iconphoto(True, icon_image)
            except:
                pass
        
        self.vault_password = None

        self.is_first_run = not os.path.exists(os.path.join(KEYS_DIR, ".vault_verifier"))

        title_text = "首次配置" if self.is_first_run else "解锁"
        self.label = ctk.CTkLabel(self, text=title_text, font=("Arial", 16, "bold"), text_color="#333333")
        self.label.pack(pady=(20, 10))
        
        desc_text = "请设置高强度主密码\n(遗失将无法恢复本地数据)" if self.is_first_run else "请输入主密码以加载核心身份与分片"
        self.desc_label = ctk.CTkLabel(self, text=desc_text, font=("Arial", 12), text_color="#666666")
        self.desc_label.pack(pady=(0, 20))

        self.entry_pwd = ctk.CTkEntry(self, show="*", width=260, placeholder_text="主密码", fg_color="#f8f8f8", text_color="#333333", border_color="#cccccc")
        self.entry_pwd.pack(pady=10)
        self.entry_pwd.bind("<Return>", self.submit)

        if self.is_first_run:
            self.entry_pwd_confirm = ctk.CTkEntry(self, show="*", width=260, placeholder_text="再次确认密码", fg_color="#f8f8f8", text_color="#333333", border_color="#cccccc")
            self.entry_pwd_confirm.pack(pady=10)
            self.entry_pwd_confirm.bind("<Return>", self.submit)

        self.btn = ctk.CTkButton(self, text="确定", command=self.submit, fg_color="#444444", hover_color="#666666", text_color="white")
        self.btn.pack(pady=20)

    def submit(self, event=None):
        pwd = self.entry_pwd.get()
        if not pwd:
            messagebox.showwarning("警告", "密码不能为空！")
            return

        if self.is_first_run:
            pwd_confirm = self.entry_pwd_confirm.get()
            if pwd != pwd_confirm:
                messagebox.showerror("错误", "两次输入的密码不一致，请重新输入！")
                self.entry_pwd.delete(0, 'end')
                self.entry_pwd_confirm.delete(0, 'end')
                return

        try:
            VaultCrypto(pwd)
            self.vault_password = pwd
            self.destroy() 
            
        except PasswordAuthError as e:
            messagebox.showerror("认证失败", str(e))
            self.entry_pwd.delete(0, 'end')
            
        except Exception as e:
            messagebox.showerror("系统异常", f"初始化时发生未知错误:\n{str(e)}")
            self.destroy()
            sys.exit(1)

class QSPApplication:
    def __init__(self, vault_password: str):
        self.vault_password = vault_password 
        self.node_id = None
        self.keypair = None
        self.p2p_node = None
        self.invite_code = None
        
        os.makedirs(KEYS_DIR, exist_ok=True)
        os.makedirs(os.path.join(DATA_DIR, "shares"), exist_ok=True)
        os.makedirs(os.path.join(DATA_DIR, "restored"), exist_ok=True)

    def initialize_identity(self):
        identity_file = os.path.join(KEYS_DIR, "node_identity.dat")
        
        vault = VaultCrypto(self.vault_password)
        
        if os.path.exists(identity_file):
            print("[System] 正在加载受保护的本地身份凭证...")
            try:

                with open(identity_file, "rb") as f:
                    encrypted_data = f.read()

                decrypted_bytes = vault.decrypt_data(encrypted_data)
  
                data = json.loads(decrypted_bytes.decode('utf-8'))
                self.node_id = data["node_id"]
                self.keypair = {
                    "pk": base64.b64decode(data["pk"]),
                    "sk": base64.b64decode(data["sk"])
                }
                
            except InvalidTag:

                error_msg = "核心身份凭证已遭到破坏！\n为保护数据安全，系统拒绝启动。"
                print(f"[Error] 安全拦截: {error_msg}")
                root = ctk.CTk()
                root.withdraw()
                messagebox.showerror("安全拦截", error_msg)
                root.destroy()
                sys.exit(1)
            except Exception as e:
                print(f"[Error] 解析身份文件时发生严重错误: {e}")
                sys.exit(1)
                
        else:
            print("[System] 首次运行，正在生成抗量子身份体系...")
            pk, sk = LatticeWrapper.generate_signing_keypair()
            import hashlib
            self.node_id = hashlib.sha256(pk).hexdigest()[:16]
            self.keypair = {"pk": pk, "sk": sk}

            identity_dict = {
                "node_id": self.node_id,
                "pk": base64.b64encode(pk).decode('utf-8'),
                "sk": base64.b64encode(sk).decode('utf-8')
            }
            plaintext_bytes = json.dumps(identity_dict).encode('utf-8')

            encrypted_bytes = vault.encrypt_data(plaintext_bytes)

            with open(identity_file, "wb") as f:
                f.write(encrypted_bytes)
        
        print(f"[System] 身份初始化成功。节点指纹: {self.node_id}")

    def start_p2p_node(self):
        self.p2p_node = P2PNode(
            host='0.0.0.0',
            port=9999,
            static_sk=self.keypair["sk"],
            dil_pk=self.keypair["pk"]
        )

        print("[P2P] 正在发现公网坐标...")
        self.p2p_node.discover_public_coordinates()

        self.p2p_node.start()

        self.invite_code = self.p2p_node.generate_invite_code()
        return self.p2p_node



def main():
    ctk.set_appearance_mode("Light")
    ctk.set_default_color_theme("dark-blue")

    login_window = LoginWindow()
    login_window.mainloop()
    
    if not login_window.vault_password:
        print("[System] 登录被用户取消，程序退出。")
        sys.exit(0)
        
    vault_password = login_window.vault_password

    app = QSPApplication(vault_password)
    app.initialize_identity()
    app.start_p2p_node()

    from GUI.main_window import MainWindow
    print("[System] 正在启动图形用户界面...")
    gui = MainWindow(app)
    gui.mainloop()
    
    if app.p2p_node:
        app.p2p_node.stop()

if __name__ == "__main__":
    main()
