"""
应用层安全路由器

负责解析解密后的业务明文，并将其分发给对应的业务模块。
核心特性：强制身份覆写机制，彻底杜绝身份伪造攻击。
"""

import logging
import traceback
from typing import Callable, Dict, Optional, Tuple
from .app_protocol import AppMessage, AppCmd, AppMessageV2, AppCmdV2


class AppRouter:
    """
    应用层消息路由器
    
    根据消息类型（命令）将消息分发给注册的处理器
    支持身份验证覆写，防止身份伪造攻击
    """
    
    def __init__(self, ui_invoker: Optional[Callable] = None):
        self.handlers: Dict = {}  # 兼容 AppCmd 和 AppCmdV2
        self.ui_invoker = ui_invoker

    def register_handler(self, cmd: AppCmd, handler: Callable):
        """注册消息处理器"""
        self.handlers[cmd] = handler

    def route_message(self, verified_source_id: str, payload: bytes):
        """
        路由解密后的业务明文数据
        
        核心安全机制：强制身份覆写。verified_source_id 来自底层 SecureLink 隔离墙，
        是抗量子双向认证提取的真实公钥指纹（不可伪造），优先于消息中自称的发送者身份。
        
        Args:
            verified_source_id: 底层密码学验证的真实公钥指纹
            payload: AES-GCM 解密后的应用层业务流
        """
        try:
            msg = AppMessageV2.decode(payload)

            if msg.sender_id != verified_source_id:
                logging.warning(
                    f"[Security] 拦截到身份伪造尝试！"
                    f"报文自称发送者为 {msg.sender_id}，但底层密码学验证其真实身份为 {verified_source_id}。"
                    f"已强制修正为真实身份！"
                )
                msg.sender_id = verified_source_id

            if msg.cmd in self.handlers:
                if self.ui_invoker:
                    self.ui_invoker(self.handlers[msg.cmd], verified_source_id, msg)
                else:
                    self.handlers[msg.cmd](verified_source_id, msg)
            else:
                logging.warning(f"[AppRouter] 收到未知或未注册的业务指令: {msg.cmd}")

        except ValueError as e:
            logging.error(f"[AppRouter] 丢弃非法格式的报文: {e}")
        except Exception as e:
            logging.error(f"[AppRouter] 路由分发时发生系统异常: {e}")
            traceback.print_exc()

    def dispatch_network_data(self, peer_addr: Tuple[str, int], raw_data: bytes):
        """分发来自网络的数据（旧版本协议兼容）"""
        try:
            msg = AppMessage.unpack(raw_data)
            
            handler = self.handlers.get(msg.cmd)
            if not handler:
                print(f"[AppRouter] 未知或未注册的业务指令丢弃: {msg.cmd}")
                return

            if self.ui_invoker:
                self.ui_invoker(handler, peer_addr, msg)
            else:
                handler(peer_addr, msg)

        except ValueError as e:
            print(f"[AppRouter] 安全拦截：接收到格式非法的应用层报文自 {peer_addr}: {e}")
        except Exception as e:
            print(f"[AppRouter] 严重错误：分发业务数据时发生异常: {e}")
            traceback.print_exc()
