"""
src/app/ui_bridge.py
[Application Phase 5] UI 状态同步与线程安全保护
提供跨线程的安全 UI 更新机制，防止后台网络线程直接修改界面导致程序崩溃死锁。
"""

import threading
from tkinter import messagebox
from typing import Optional, Callable, Any


class UIBridge:
    def __init__(self, root):
        self.root = root
        
        self.lbl_net_status: Any = None
        self.progress_bar: Any = None
        self.btn_backup: Any = None
        self.btn_recovery: Any = None

    def bind_widgets(self, lbl_net_status, progress_bar, btn_backup, btn_recovery):
        self.lbl_net_status = lbl_net_status
        self.progress_bar = progress_bar
        self.btn_backup = btn_backup
        self.btn_recovery = btn_recovery

    def run_in_main_thread(self, func: Callable, *args, **kwargs):
        if not self.root:
            return
        
        def wrapper():
            try:
                func(*args, **kwargs)
            except Exception as e:
                print(f"[UI Bridge Error] 跨线程执行 UI 更新失败: {e}")
                
        self.root.after(0, wrapper)

    def safe_update_net_status(self, text: str, text_color: str = "white"):
        def _update():
            if self.lbl_net_status:
                try:
                    self.lbl_net_status.configure(text=text, text_color=text_color)
                except (AttributeError, Exception):
                    try:
                        self.lbl_net_status.config(text=text, fg=text_color)
                    except Exception:
                        pass
        self.run_in_main_thread(_update)

    def safe_update_progress(self, current: int, total: int):
        def _update():
            if self.progress_bar and total > 0:
                val = float(current) / float(total)
                try:
                    self.progress_bar.set(val)
                except (AttributeError, Exception):
                    try:
                        self.progress_bar['value'] = val * 100
                    except Exception:
                        pass
        self.run_in_main_thread(_update)

    def safe_show_info(self, title: str, message: str):
        self.run_in_main_thread(messagebox.showinfo, title, message)

    def safe_show_error(self, title: str, message: str):
        self.run_in_main_thread(messagebox.showerror, title, message)

    def safe_set_action_buttons_state(self, state: str):
        def _update():
            if self.btn_backup:
                try:
                    self.btn_backup.configure(state=state)
                except Exception:
                    pass
            if self.btn_recovery:
                try:
                    self.btn_recovery.configure(state=state)
                except Exception:
                    pass
        self.run_in_main_thread(_update)
