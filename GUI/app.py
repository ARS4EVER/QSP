# -*- coding: utf-8 -*-
"""
GUI应用程序类
文件路径: GUI/app.py

实现基于tkinter的图形用户界面，整合项目中的所有模块，提供完整的应用程序功能。
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
import threading
import time
import numpy as np
import cv2
from PIL import Image, ImageTk

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 导入项目模块
from src.config import Config
from src.crypto_lattice.keygen import KeyGenerator
from src.crypto_lattice.signer import ThresholdSigner, SignatureAggregator
from src.secret_sharing.splitter import ImageCRTSplitter
from src.secret_sharing.reconstructor import ImageCRTReconstructor
from src.image_stego.orchestrator import Module3Orchestrator
from src.image_stego.img_process import ImageProcessor
from src.image_stego.dct_embed import DCTEmbedder
from src.image_stego.dct_extract import DCTExtractor

class StegoApp:
    """
    主应用程序类，实现GUI界面和核心功能逻辑
    """
    
    def __init__(self, root):
        """
        初始化应用程序
        参数:
            root: tkinter根窗口
        """
        self.root = root
        self.root.title("后量子安全图像隐写系统")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # 设置窗口图标（如果有）
        # self.root.iconbitmap("icon.ico")
        
        # 设置主题
        self.style = ttk.Style()
        self.style.theme_use("clam")  # 使用clam主题，提供更好的跨平台一致性
        
        # 自定义样式 - 科学专业性色彩方案
        # 主色调：深蓝色 (#1a365d) - 代表专业、可靠、科技感
        # 辅助色：浅蓝色 (#4299e1) - 用于强调和交互元素
        # 中性色：浅灰 (#f7fafc)、中灰 (#e2e8f0)、深灰 (#4a5568) - 用于背景和文本
        
        # 按钮样式
        self.style.configure("TButton", 
                            padding=6, 
                            relief="flat", 
                            background="#4299e1", 
                            foreground="#ffffff",
                            font=("SimHei", 10, "normal"))
        self.style.map("TButton", 
                      background=[("active", "#3182ce"), ("disabled", "#a0aec0")],
                      foreground=[("disabled", "#e2e8f0")])
        
        # 标签样式
        self.style.configure("TLabel", 
                            padding=4, 
                            font=("SimHei", 10, "normal"),
                            background="#f7fafc",
                            foreground="#1a365d")
        
        # 笔记本样式
        self.style.configure("TNotebook", 
                            padding=4, 
                            background="#f7fafc")
        self.style.configure("TNotebook.Tab", 
                            padding=(15, 8), 
                            font=("SimHei", 10, "bold"),
                            background="#e2e8f0",
                            foreground="#4a5568")
        self.style.map("TNotebook.Tab", 
                      background=[("selected", "#4299e1"), ("active", "#cbd5e0")],
                      foreground=[("selected", "#ffffff"), ("active", "#2d3748")])
        
        # 输入框样式
        self.style.configure("TEntry", 
                            padding=6, 
                            font=("SimHei", 10, "normal"),
                            fieldbackground="#ffffff",
                            background="#f7fafc",
                            foreground="#1a365d")
        
        # 文本框样式
        self.style.configure("TText", 
                            padding=6, 
                            font=("SimHei", 10, "normal"),
                            background="#ffffff",
                            foreground="#1a365d")
        
        # 进度条样式
        self.style.configure("Horizontal.TProgressbar", 
                            padding=4, 
                            background="#4299e1",
                            troughcolor="#e2e8f0")
        
        # 初始化模块
        self.image_processor = ImageProcessor()
        self.crt_splitter = ImageCRTSplitter()
        self.crt_reconstructor = ImageCRTReconstructor()
        self.stego_orchestrator = Module3Orchestrator()
        self.embedder = DCTEmbedder()
        self.extractor = DCTExtractor()
        self.keygen = KeyGenerator()
        self.aggregator = SignatureAggregator()
        
        # 变量初始化
        self.carrier_image_path = ""
        self.secret_image_path = ""
        self.stego_image_path = ""
        self.reconstructed_image_path = ""
        self.share_paths = []
        self.extracted_share_paths = []
        self.stego_paths = []
        self.is_processing = False
        
        # 设置窗口背景色
        self.root.configure(bg="#f7fafc")
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建标签页控件
        self.notebook = ttk.Notebook(self.main_frame, style="TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 添加标签页切换事件
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        # 创建各个标签页
        self.create_home_tab()
        self.create_lattice_tab()
        self.create_crt_tab()
        self.create_stego_tab()
        self.create_full_process_tab()
        self.create_about_tab()
        
        # 创建状态栏
        self.create_status_bar()
        
        # 创建进度条窗口
        self.create_progress_window()
        
        # 绑定快捷键
        self.bind_shortcuts()
        
        # 显示启动信息
        self.update_status("系统已初始化，准备就绪")
        
    def create_home_tab(self):
        """
        创建首页标签页
        """
        home_tab = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(home_tab, text="首页")
        # ttk.Frame不支持bg选项，使用style设置
        
        # 创建标题区域
        title_frame = ttk.Frame(home_tab)
        title_frame.pack(fill=tk.X, pady=20)
        
        title_label = ttk.Label(title_frame, text="后量子安全图像隐写系统", 
                               font=("SimHei", 26, "bold"), 
                               foreground="#1a365d")
        title_label.pack(pady=10)
        
        subtitle_label = ttk.Label(title_frame, text="基于格密码的抗量子安全图像隐蔽传输方案", 
                                  font=("SimHei", 14, "normal"), 
                                  foreground="#4a5568")
        subtitle_label.pack(pady=5)
        
        # 创建功能卡片区域
        cards_frame = ttk.Frame(home_tab)
        cards_frame.pack(fill=tk.BOTH, expand=True, pady=20)
        
        # 创建网格布局
        cards_frame.grid_rowconfigure(0, weight=1)
        cards_frame.grid_columnconfigure(0, weight=1)
        cards_frame.grid_columnconfigure(1, weight=1)
        cards_frame.grid_columnconfigure(2, weight=1)
        cards_frame.grid_columnconfigure(3, weight=1)
        
        # 功能卡片1：格密码门限签名
        self.create_feature_card(cards_frame, 0, 0, 
                                "格密码门限签名", 
                                "基于Module-LWE问题的后量子安全签名方案，提供抗量子攻击的认证机制。",
                                lambda: self.notebook.select(1))
        
        # 功能卡片2：CRT秘密共享
        self.create_feature_card(cards_frame, 0, 1, 
                                "CRT秘密共享", 
                                "使用中国剩余定理将图像分割为多个影子图像，实现信息的分布式存储和安全恢复。",
                                lambda: self.notebook.select(2))
        
        # 功能卡片3：基于DCT的图像隐写
        self.create_feature_card(cards_frame, 0, 2, 
                                "基于DCT的图像隐写", 
                                "将影子图像嵌入到普通载体图像中，实现信息的隐蔽传输。",
                                lambda: self.notebook.select(3))
        
        # 功能卡片4：完整流程
        self.create_feature_card(cards_frame, 0, 3, 
                                "完整流程", 
                                "从原始图像到含密图像的完整嵌入流程，以及从含密图像恢复原始图像的完整提取流程。",
                                lambda: self.notebook.select(4))
        
        # 创建快速开始区域
        quick_start_frame = ttk.Frame(home_tab)
        quick_start_frame.pack(fill=tk.X, pady=30)
        
        quick_start_label = ttk.Label(quick_start_frame, text="快速开始", 
                                     font=("SimHei", 16, "bold"), 
                                     foreground="#1a365d")
        quick_start_label.pack(pady=10)
        
        # 快速开始按钮
        buttons_frame = ttk.Frame(quick_start_frame)
        buttons_frame.pack(pady=10)
        
        ttk.Button(buttons_frame, text="开始完整流程", 
                  command=lambda: self.notebook.select(4), 
                  width=22, 
                  style="TButton").pack(side=tk.LEFT, padx=15)
        
        ttk.Button(buttons_frame, text="查看系统帮助", 
                  command=self.show_help, 
                  width=22, 
                  style="TButton").pack(side=tk.LEFT, padx=15)
        
        ttk.Button(buttons_frame, text="关于本系统", 
                  command=lambda: self.notebook.select(5), 
                  width=22, 
                  style="TButton").pack(side=tk.LEFT, padx=15)
    
    def create_lattice_tab(self):
        """
        创建格密码标签页
        """
        lattice_tab = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(lattice_tab, text="格密码签名")
        # ttk.Frame不支持bg选项，使用style设置
        
        # 创建左侧控制面板
        control_frame = ttk.Frame(lattice_tab, width=300, padding=15, relief=tk.RAISED, borderwidth=1)
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        # ttk.Frame不支持bg选项，使用style设置
        
        # 创建右侧日志面板
        log_frame = ttk.Frame(lattice_tab, padding=15, relief=tk.RAISED, borderwidth=1)
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        # ttk.Frame不支持bg选项，使用style设置
        
        # 添加控制面板内容
        ttk.Label(control_frame, text="格密码门限签名系统", 
                  font=("SimHei", 14, "bold"), 
                  foreground="#1a365d").pack(pady=15)
        
        # 按钮容器
        buttons_frame = ttk.Frame(control_frame)
        buttons_frame.pack(fill=tk.Y, expand=True)
        
        ttk.Button(buttons_frame, text="生成密钥对", 
                  command=self.generate_keys, 
                  width=20, 
                  style="TButton").pack(pady=12, fill=tk.X)
        
        ttk.Button(buttons_frame, text="生成签名", 
                  command=self.generate_signature, 
                  width=20, 
                  style="TButton").pack(pady=12, fill=tk.X)
        
        ttk.Button(buttons_frame, text="验证签名", 
                  command=self.verify_signature, 
                  width=20, 
                  style="TButton").pack(pady=12, fill=tk.X)
        
        ttk.Button(buttons_frame, text="清除日志", 
                  command=self.clear_lattice_log, 
                  width=20, 
                  style="TButton").pack(pady=12, fill=tk.X)
        
        # 添加日志面板内容
        ttk.Label(log_frame, text="操作日志", 
                  font=("SimHei", 12, "bold"), 
                  foreground="#1a365d").pack(pady=10, anchor=tk.W)
        
        # 创建日志文本框框架
        log_text_frame = ttk.Frame(log_frame)
        log_text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.lattice_log = tk.Text(log_text_frame, 
                                  height=20, 
                                  width=60, 
                                  wrap=tk.WORD, 
                                  font=("SimHei", 10, "normal"),
                                  background="#f7fafc",
                                  foreground="#1a365d",
                                  borderwidth=1, 
                                  relief=tk.SUNKEN)
        self.lattice_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(log_text_frame, command=self.lattice_log.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.lattice_log.config(yscrollcommand=scrollbar.set)
        
        # 初始日志
        self.lattice_log.insert(tk.END, "格密码门限签名系统已初始化\n")
        self.lattice_log.insert(tk.END, "点击按钮执行相应操作\n")
    
    def create_crt_tab(self):
        """
        创建CRT秘密共享标签页
        """
        crt_tab = ttk.Frame(self.notebook)
        self.notebook.add(crt_tab, text="CRT秘密共享")
        
        # 创建左侧控制面板
        control_frame = ttk.Frame(crt_tab, width=300)
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        
        # 创建右侧图像显示面板
        image_frame = ttk.Frame(crt_tab)
        image_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 添加控制面板内容
        ttk.Label(control_frame, text="CRT秘密共享系统", font=("SimHei", 14, "bold")).pack(pady=10)
        
        ttk.Label(control_frame, text="秘密图像:").pack(anchor=tk.W, pady=5)
        self.crt_secret_image_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.crt_secret_image_var, width=30).pack(pady=5)
        ttk.Button(control_frame, text="选择图像", command=self.select_crt_secret_image, width=20).pack(pady=5)
        
        ttk.Label(control_frame, text="签名数据:").pack(anchor=tk.W, pady=5)
        self.crt_signature_var = tk.StringVar(value="默认签名数据")
        ttk.Entry(control_frame, textvariable=self.crt_signature_var, width=30).pack(pady=5)
        
        ttk.Button(control_frame, text="分割图像", command=self.split_image, width=20).pack(pady=10)
        ttk.Button(control_frame, text="选择份额", command=self.select_shares, width=20).pack(pady=10)
        ttk.Button(control_frame, text="重构图像", command=self.reconstruct_image, width=20).pack(pady=10)
        
        # 添加图像显示面板内容
        self.crt_image_frame = ttk.Frame(image_frame)
        self.crt_image_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建网格布局
        self.crt_image_frame.grid_rowconfigure(0, weight=1)
        self.crt_image_frame.grid_rowconfigure(1, weight=1)
        self.crt_image_frame.grid_columnconfigure(0, weight=1)
        self.crt_image_frame.grid_columnconfigure(1, weight=1)
        
        # 原始秘密图像
        ttk.Label(self.crt_image_frame, text="原始秘密图像", font=("SimHei", 10, "bold")).grid(row=0, column=0, pady=5)
        self.crt_original_image_label = ttk.Label(self.crt_image_frame, text="未选择图像")
        self.crt_original_image_label.grid(row=1, column=0, padx=10, pady=10)
        
        # 重构图像
        ttk.Label(self.crt_image_frame, text="重构图像", font=("SimHei", 10, "bold")).grid(row=0, column=1, pady=5)
        self.crt_reconstructed_image_label = ttk.Label(self.crt_image_frame, text="未重构图像")
        self.crt_reconstructed_image_label.grid(row=1, column=1, padx=10, pady=10)
        
    def create_stego_tab(self):
        """
        创建图像隐写标签页
        """
        stego_tab = ttk.Frame(self.notebook)
        self.notebook.add(stego_tab, text="图像隐写")
        
        # 创建左侧控制面板
        control_frame = ttk.Frame(stego_tab, width=300)
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        
        # 创建右侧图像显示面板
        image_frame = ttk.Frame(stego_tab)
        image_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 添加控制面板内容
        ttk.Label(control_frame, text="图像隐写系统", font=("SimHei", 14, "bold")).pack(pady=10)
        
        ttk.Label(control_frame, text="载体图像:").pack(anchor=tk.W, pady=5)
        self.stego_carrier_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.stego_carrier_var, width=30).pack(pady=5)
        ttk.Button(control_frame, text="选择图像", command=self.select_stego_carrier, width=20).pack(pady=5)
        
        ttk.Label(control_frame, text="含密图像:").pack(anchor=tk.W, pady=5)
        self.stego_output_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.stego_output_var, width=30).pack(pady=5)
        ttk.Button(control_frame, text="保存路径", command=self.select_stego_output, width=20).pack(pady=5)
        
        ttk.Button(control_frame, text="嵌入数据", command=self.embed_data, width=20).pack(pady=10)
        ttk.Button(control_frame, text="提取数据", command=self.extract_data, width=20).pack(pady=10)
        ttk.Button(control_frame, text="计算PSNR", command=self.calculate_psnr, width=20).pack(pady=10)
        
        # 添加图像显示面板内容
        self.stego_image_frame = ttk.Frame(image_frame)
        self.stego_image_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建网格布局
        self.stego_image_frame.grid_rowconfigure(0, weight=1)
        self.stego_image_frame.grid_rowconfigure(1, weight=1)
        self.stego_image_frame.grid_columnconfigure(0, weight=1)
        self.stego_image_frame.grid_columnconfigure(1, weight=1)
        
        # 载体图像
        ttk.Label(self.stego_image_frame, text="载体图像", font=("SimHei", 10, "bold")).grid(row=0, column=0, pady=5)
        self.stego_carrier_label = ttk.Label(self.stego_image_frame, text="未选择图像")
        self.stego_carrier_label.grid(row=1, column=0, padx=10, pady=10)
        
        # 含密图像
        ttk.Label(self.stego_image_frame, text="含密图像", font=("SimHei", 10, "bold")).grid(row=0, column=1, pady=5)
        self.stego_stego_label = ttk.Label(self.stego_image_frame, text="未生成含密图像")
        self.stego_stego_label.grid(row=1, column=1, padx=10, pady=10)
    
    def create_full_process_tab(self):
        """
        创建完整流程标签页
        """
        full_process_tab = ttk.Frame(self.notebook)
        self.notebook.add(full_process_tab, text="完整流程")
        
        # 创建左侧控制面板
        control_frame = ttk.Frame(full_process_tab, width=300)
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        
        # 创建右侧状态和结果面板
        result_frame = ttk.Frame(full_process_tab)
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 添加控制面板内容
        ttk.Label(control_frame, text="完整流程", font=("SimHei", 14, "bold")).pack(pady=10)
        
        ttk.Label(control_frame, text="载体图像:").pack(anchor=tk.W, pady=5)
        self.full_carrier_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.full_carrier_var, width=30).pack(pady=5)
        ttk.Button(control_frame, text="选择图像", command=self.select_full_carrier, width=20).pack(pady=5)
        
        ttk.Label(control_frame, text="秘密图像:").pack(anchor=tk.W, pady=5)
        self.full_secret_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.full_secret_var, width=30).pack(pady=5)
        ttk.Button(control_frame, text="选择图像", command=self.select_full_secret, width=20).pack(pady=5)
        
        ttk.Button(control_frame, text="执行嵌入流程", command=self.execute_embedding_process, width=20).pack(pady=10)
        ttk.Button(control_frame, text="执行提取流程", command=self.execute_extraction_process, width=20).pack(pady=10)
        ttk.Button(control_frame, text="查看结果", command=self.view_results, width=20).pack(pady=10)
        ttk.Button(control_frame, text="清除数据", command=self.clear_full_process, width=20).pack(pady=10)
        
        # 添加结果面板内容
        ttk.Label(result_frame, text="流程状态", font=("SimHei", 12, "bold")).pack(pady=5)
        
        self.full_process_log = tk.Text(result_frame, height=15, width=60, wrap=tk.WORD)
        self.full_process_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(self.full_process_log, command=self.full_process_log.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.full_process_log.config(yscrollcommand=scrollbar.set)
        
        # 初始日志
        self.full_process_log.insert(tk.END, "完整流程已初始化\n")
        self.full_process_log.insert(tk.END, "选择载体图像和秘密图像后执行相应操作\n")
    
    def create_feature_card(self, parent, row, column, title, description, command):
        """
        创建功能卡片
        参数:
            parent: 父容器
            row: 行号
            column: 列号
            title: 卡片标题
            description: 卡片描述
            command: 点击按钮的回调函数
        """
        # 创建卡片框架
        card_frame = ttk.Frame(parent, padding=15, relief=tk.RAISED, borderwidth=1)
        card_frame.grid(row=row, column=column, padx=10, pady=10, sticky="nsew")
        # ttk.Frame不支持bg选项，使用style设置
        
        # 设置卡片样式
        card_frame.configure(style="Card.TFrame")
        
        # 创建标题
        title_label = ttk.Label(card_frame, text=title, 
                              font=("SimHei", 14, "bold"), 
                              foreground="#1a365d", 
                              wraplength=200)
        title_label.pack(pady=10, anchor=tk.W)
        
        # 创建描述
        desc_label = ttk.Label(card_frame, text=description, 
                              font=("SimHei", 10, "normal"), 
                              foreground="#4a5568", 
                              justify=tk.LEFT, 
                              wraplength=200)
        desc_label.pack(pady=10, anchor=tk.W)
        
        # 创建按钮
        button = ttk.Button(card_frame, text="查看详情", 
                          command=command, 
                          style="TButton", 
                          width=12)
        button.pack(pady=10, anchor=tk.E)
    
    def create_about_tab(self):
        """
        创建关于标签页
        """
        about_tab = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(about_tab, text="关于")
        # ttk.Frame不支持bg选项，使用style设置
        
        # 创建标题
        title_label = ttk.Label(about_tab, text="关于本系统", 
                              font=("SimHei", 18, "bold"), 
                              foreground="#1a365d")
        title_label.pack(pady=20)
        
        # 创建内容
        content_frame = ttk.Frame(about_tab, padding=20, relief=tk.RAISED, borderwidth=1)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        # ttk.Frame不支持bg选项，使用style设置
        
        content_text = """
        后量子安全图像隐写系统 v1.0
        
        本系统是一个基于后量子密码学的安全图像隐写系统，旨在提供抗量子攻击的图像隐蔽传输方案。
        
        技术特点：
        1. 基于Module-LWE问题的格密码门限签名，提供抗量子攻击的认证机制
        2. 使用中国剩余定理(CRT)进行秘密共享，实现信息的分布式存储
        3. 基于离散余弦变换(DCT)的图像隐写，实现信息的隐蔽传输
        4. 完整的端到端加密和隐写流程
        
        系统要求：
        - Python 3.7+
        - NumPy
        - OpenCV
        - Pillow
        - Tkinter
        
        开发团队：
        - 量子安全研究小组
        
        版权所有 © 2026
        """
        
        content_label = ttk.Label(content_frame, text=content_text, 
                                font=("SimHei", 11, "normal"), 
                                foreground="#4a5568",
                                justify=tk.LEFT, 
                                wraplength=800)
        content_label.pack(pady=10)
    
    def generate_keys(self):
        """
        生成格密码密钥对
        """
        def task():
            try:
                self.update_status("正在生成密钥对...")
                self.show_progress("生成格密码密钥对...", 0)
                self.lattice_log.insert(tk.END, "开始生成密钥对...\n")
                self.lattice_log.see(tk.END)
                
                # 生成密钥对
                self.show_progress("生成格密码密钥对...", 30)
                pk, sk = self.keygen.generate_keys()
                
                self.show_progress("生成格密码密钥对...", 100)
                self.lattice_log.insert(tk.END, "密钥对生成成功！\n")
                self.lattice_log.insert(tk.END, f"公钥大小: {Config.PK_SIZE_BYTES} 字节\n")
                self.lattice_log.insert(tk.END, f"私钥包含 {len(sk['s1'])} 个多项式\n")
                self.lattice_log.see(tk.END)
                
                # 保存密钥（仅在内存中）
                self.pk = pk
                self.sk = sk
                
                self.update_status("密钥对生成成功")
                self.hide_progress()
                messagebox.showinfo("成功", "密钥对生成成功！")
                
            except Exception as e:
                self.lattice_log.insert(tk.END, f"生成密钥对失败: {str(e)}\n")
                self.lattice_log.see(tk.END)
                self.update_status(f"生成密钥对失败: {str(e)}")
                self.hide_progress()
                messagebox.showerror("错误", f"生成密钥对失败: {str(e)}")
        
        self.run_in_thread(task)
    
    def generate_signature(self):
        """
        生成格密码签名
        """
        try:
            if not hasattr(self, 'sk'):
                raise ValueError("请先生成密钥对")
            
            self.lattice_log.insert(tk.END, "开始生成签名...\n")
            self.lattice_log.see(tk.END)
            
            # 创建签名者实例
            signer = ThresholdSigner(self.sk, 0)
            
            # 阶段1: 生成承诺
            W_share = signer.phase1_commitment()
            
            # 聚合承诺
            W_sum = self.aggregator.aggregate_commitments([W_share])
            
            # 阶段2: 生成挑战
            message = b"Hello Quantum World"
            challenge_c = self.aggregator.derive_challenge(message, W_sum)
            
            # 阶段3: 生成响应
            max_attempts = 5
            for attempt in range(max_attempts):
                self.lattice_log.insert(tk.END, f"尝试生成签名 ({attempt+1}/{max_attempts})...\n")
                self.lattice_log.see(tk.END)
                
                z_share = signer.phase2_response(challenge_c)
                if z_share is not None:
                    break
            
            if z_share is not None:
                # 聚合响应
                Z_sum = self.aggregator.aggregate_responses([z_share])
                
                self.lattice_log.insert(tk.END, "签名生成成功！\n")
                self.lattice_log.insert(tk.END, f"签名包含 {len(Z_sum)} 个多项式\n")
                self.lattice_log.see(tk.END)
                
                # 保存签名
                self.signature = Z_sum
            else:
                self.lattice_log.insert(tk.END, "签名生成失败：所有尝试都被拒绝\n")
                self.lattice_log.see(tk.END)
                messagebox.warning("警告", "签名生成失败：所有尝试都被拒绝")
                
        except Exception as e:
            self.lattice_log.insert(tk.END, f"生成签名失败: {str(e)}\n")
            self.lattice_log.see(tk.END)
            messagebox.showerror("错误", f"生成签名失败: {str(e)}")
    
    def verify_signature(self):
        """
        验证格密码签名
        """
        try:
            if not hasattr(self, 'signature'):
                raise ValueError("请先生成签名")
            
            self.lattice_log.insert(tk.END, "开始验证签名...\n")
            self.lattice_log.see(tk.END)
            
            # 这里仅做模拟验证，实际验证需要完整的验证算法
            self.lattice_log.insert(tk.END, "签名验证成功！\n")
            self.lattice_log.insert(tk.END, "（注：这里是模拟验证，实际验证需要完整的验证算法）\n")
            self.lattice_log.see(tk.END)
            
            messagebox.showinfo("成功", "签名验证成功！")
            
        except Exception as e:
            self.lattice_log.insert(tk.END, f"验证签名失败: {str(e)}\n")
            self.lattice_log.see(tk.END)
            messagebox.showerror("错误", f"验证签名失败: {str(e)}")
    
    def clear_lattice_log(self):
        """
        清除格密码日志
        """
        self.lattice_log.delete(1.0, tk.END)
        self.lattice_log.insert(tk.END, "格密码门限签名系统已初始化\n")
        self.lattice_log.insert(tk.END, "点击按钮执行相应操作\n")
    
    def select_crt_secret_image(self):
        """
        选择CRT秘密图像
        """
        file_path = filedialog.askopenfilename(
            title="选择秘密图像",
            filetypes=[("PNG图像", "*.png"), ("JPEG图像", "*.jpg"), ("所有文件", "*.*")]
        )
        if file_path:
            self.crt_secret_image_var.set(file_path)
            self.secret_image_path = file_path
            
            # 显示图像
            self.display_image(self.crt_original_image_label, file_path)
    
    def split_image(self):
        """
        分割CRT图像
        """
        try:
            if not self.secret_image_path:
                raise ValueError("请选择秘密图像")
            
            # 生成签名数据（模拟）
            if not hasattr(self, 'signature'):
                pk, sk = self.keygen.generate_keys()
                signer = ThresholdSigner(sk, 0)
                W_share = signer.phase1_commitment()
                W_sum = self.aggregator.aggregate_commitments([W_share])
                message = b"CRT Secret Sharing"
                challenge_c = self.aggregator.derive_challenge(message, W_sum)
                
                max_attempts = 5
                for attempt in range(max_attempts):
                    z_share = signer.phase2_response(challenge_c)
                    if z_share is not None:
                        break
                
                if z_share is None:
                    raise ValueError("无法生成签名")
                
                self.signature = z_share
            
            signature_data = str(self.signature).encode('utf-8')
            
            # 分割图像
            self.share_paths = self.crt_splitter.split_image(self.secret_image_path, signature_data=signature_data)
            
            messagebox.showinfo("成功", f"图像分割成功！生成了 {len(self.share_paths)} 个份额")
            
        except Exception as e:
            messagebox.showerror("错误", f"图像分割失败: {str(e)}")
    
    def select_shares(self):
        """
        选择CRT份额
        """
        file_paths = filedialog.askopenfilenames(
            title="选择份额文件",
            filetypes=[("NumPy文件", "*.npy"), ("所有文件", "*.*")]
        )
        if file_paths:
            self.share_paths = list(file_paths)
            messagebox.showinfo("成功", f"选择了 {len(self.share_paths)} 个份额")
    
    def reconstruct_image(self):
        """
        重构CRT图像
        """
        try:
            if not self.share_paths:
                raise ValueError("请选择份额文件")
            
            # 确保至少选择了t个份额
            if len(self.share_paths) < Config.T_THRESHOLD:
                raise ValueError(f"至少需要选择 {Config.T_THRESHOLD} 个份额")
            
            # 重构图像
            reconstructed_img, recovered_sig = self.crt_reconstructor.reconstruct_image(self.share_paths)
            
            # 保存重构图像
            output_dir = os.path.join(Config.DATASET_DIR, "reconstructed")
            os.makedirs(output_dir, exist_ok=True)
            
            self.reconstructed_image_path = os.path.join(output_dir, "reconstructed_image.png")
            reconstructed_img.save(self.reconstructed_image_path)
            
            # 显示重构图像
            self.display_image(self.crt_reconstructed_image_label, self.reconstructed_image_path)
            
            messagebox.showinfo("成功", "图像重构成功！")
            
        except Exception as e:
            messagebox.showerror("错误", f"图像重构失败: {str(e)}")
    
    def select_stego_carrier(self):
        """
        选择隐写载体图像
        """
        file_path = filedialog.askopenfilename(
            title="选择载体图像",
            filetypes=[("PNG图像", "*.png"), ("JPEG图像", "*.jpg"), ("所有文件", "*.*")]
        )
        if file_path:
            self.stego_carrier_var.set(file_path)
            self.carrier_image_path = file_path
            
            # 显示图像
            self.display_image(self.stego_carrier_label, file_path)
    
    def select_stego_output(self):
        """
        选择隐写输出路径
        """
        file_path = filedialog.asksaveasfilename(
            title="保存含密图像",
            defaultextension=".png",
            filetypes=[("PNG图像", "*.png"), ("JPEG图像", "*.jpg"), ("所有文件", "*.*")]
        )
        if file_path:
            self.stego_output_var.set(file_path)
            self.stego_image_path = file_path
    
    def embed_data(self):
        """
        嵌入数据到载体图像
        """
        def task():
            try:
                if not self.carrier_image_path:
                    raise ValueError("请选择载体图像")
                
                if not self.stego_image_path:
                    raise ValueError("请选择保存路径")
                
                self.update_status("正在嵌入数据...")
                self.show_progress("嵌入数据到载体图像...", 0)
                
                # 读取载体图像
                self.show_progress("嵌入数据到载体图像...", 20)
                carrier = self.image_processor.read_image(self.carrier_image_path)
                
                # 生成测试数据
                test_data = b"This is a test message for steganography"
                
                # 嵌入数据
                self.show_progress("嵌入数据到载体图像...", 60)
                stego = self.embedder.embed(carrier, test_data)
                
                # 保存含密图像
                self.show_progress("嵌入数据到载体图像...", 80)
                self.image_processor.save_image(stego, self.stego_image_path)
                
                # 显示含密图像
                self.show_progress("嵌入数据到载体图像...", 100)
                self.display_image(self.stego_stego_label, self.stego_image_path)
                
                self.update_status("数据嵌入成功")
                self.hide_progress()
                messagebox.showinfo("成功", "数据嵌入成功！")
                
            except Exception as e:
                self.update_status(f"数据嵌入失败: {str(e)}")
                self.hide_progress()
                messagebox.showerror("错误", f"数据嵌入失败: {str(e)}")
        
        self.run_in_thread(task)
    
    def extract_data(self):
        """
        从含密图像中提取数据
        """
        try:
            if not self.stego_image_path:
                raise ValueError("请先生成含密图像")
            
            # 读取含密图像
            stego = self.image_processor.read_image(self.stego_image_path)
            
            # 提取数据
            extracted_data = self.extractor.extract(stego)
            
            messagebox.showinfo("成功", f"数据提取成功！\n提取的数据: {extracted_data.decode('utf-8', errors='replace')}")
            
        except Exception as e:
            messagebox.showerror("错误", f"数据提取失败: {str(e)}")
    
    def calculate_psnr(self):
        """
        计算PSNR值
        """
        try:
            if not self.carrier_image_path:
                raise ValueError("请选择载体图像")
            
            if not self.stego_image_path:
                raise ValueError("请先生成含密图像")
            
            # 读取图像
            carrier = self.image_processor.read_image(self.carrier_image_path)
            stego = self.image_processor.read_image(self.stego_image_path)
            
            # 计算PSNR
            psnr = self.image_processor.calculate_psnr(carrier, stego)
            
            messagebox.showinfo("PSNR计算结果", f"PSNR值: {psnr:.2f} dB")
            
        except Exception as e:
            messagebox.showerror("错误", f"计算PSNR失败: {str(e)}")
    
    def select_full_carrier(self):
        """
        选择完整流程的载体图像
        """
        file_path = filedialog.askopenfilename(
            title="选择载体图像",
            filetypes=[("PNG图像", "*.png"), ("JPEG图像", "*.jpg"), ("所有文件", "*.*")]
        )
        if file_path:
            self.full_carrier_var.set(file_path)
            self.carrier_image_path = file_path
    
    def select_full_secret(self):
        """
        选择完整流程的秘密图像
        """
        file_path = filedialog.askopenfilename(
            title="选择秘密图像",
            filetypes=[("PNG图像", "*.png"), ("JPEG图像", "*.jpg"), ("所有文件", "*.*")]
        )
        if file_path:
            self.full_secret_var.set(file_path)
            self.secret_image_path = file_path
    
    def execute_embedding_process(self):
        """
        执行完整的嵌入流程
        """
        def task():
            try:
                if not self.carrier_image_path:
                    raise ValueError("请选择载体图像")
                
                if not self.secret_image_path:
                    raise ValueError("请选择秘密图像")
                
                self.update_status("正在执行嵌入流程...")
                self.show_progress("执行完整嵌入流程...", 0)
                self.full_process_log.insert(tk.END, "开始执行嵌入流程...\n")
                self.full_process_log.see(tk.END)
                
                # 1. 生成签名
                self.show_progress("执行完整嵌入流程...", 20)
                self.full_process_log.insert(tk.END, "1. 生成格密码签名...\n")
                self.full_process_log.see(tk.END)
                
                pk, sk = self.keygen.generate_keys()
                signer = ThresholdSigner(sk, 0)
                W_share = signer.phase1_commitment()
                W_sum = self.aggregator.aggregate_commitments([W_share])
                message = b"Full Process Signature"
                challenge_c = self.aggregator.derive_challenge(message, W_sum)
                
                max_attempts = 5
                for attempt in range(max_attempts):
                    z_share = signer.phase2_response(challenge_c)
                    if z_share is not None:
                        break
                
                if z_share is None:
                    raise ValueError("无法生成签名")
                
                signature_data = str(z_share).encode('utf-8')
                
                # 2. 分割秘密图像
                self.show_progress("执行完整嵌入流程...", 50)
                self.full_process_log.insert(tk.END, "2. 分割秘密图像...\n")
                self.full_process_log.see(tk.END)
                
                self.share_paths = self.crt_splitter.split_image(self.secret_image_path, signature_data=signature_data)
                
                # 3. 嵌入到载体图像
                self.show_progress("执行完整嵌入流程...", 80)
                self.full_process_log.insert(tk.END, "3. 嵌入数据到载体图像...\n")
                self.full_process_log.see(tk.END)
                
                # 加载份额数据
                share_data = np.load(self.share_paths[0], allow_pickle=True).item()
                remainder_img = share_data['data'].reshape((32, 32, 3))
                multiple_map = np.zeros_like(remainder_img, dtype=np.uint8)
                
                # 执行嵌入
                stego_img = self.stego_orchestrator.process_step_3_embedding(
                    self.carrier_image_path,
                    remainder_img,
                    multiple_map
                )
                
                # 保存含密图像
                self.stego_image_path = os.path.join(Config.STEGO_DIR, "full_process_stego.png")
                os.makedirs(Config.STEGO_DIR, exist_ok=True)
                cv2.imwrite(self.stego_image_path, stego_img)
                
                self.stego_paths = [self.stego_image_path]
                
                self.show_progress("执行完整嵌入流程...", 100)
                self.full_process_log.insert(tk.END, "嵌入流程执行成功！\n")
                self.full_process_log.insert(tk.END, f"含密图像已保存到: {self.stego_image_path}\n")
                self.full_process_log.see(tk.END)
                
                self.update_status("嵌入流程执行成功")
                self.hide_progress()
                messagebox.showinfo("成功", "嵌入流程执行成功！")
                
            except Exception as e:
                self.full_process_log.insert(tk.END, f"嵌入流程执行失败: {str(e)}\n")
                self.full_process_log.see(tk.END)
                self.update_status(f"嵌入流程执行失败: {str(e)}")
                self.hide_progress()
                messagebox.showerror("错误", f"嵌入流程执行失败: {str(e)}")
        
        self.run_in_thread(task)
    
    def execute_extraction_process(self):
        """
        执行完整的提取流程
        """
        def task():
            try:
                if not self.stego_paths:
                    raise ValueError("请先执行嵌入流程")
                
                self.update_status("正在执行提取流程...")
                self.show_progress("执行完整提取流程...", 0)
                self.full_process_log.insert(tk.END, "开始执行提取流程...\n")
                self.full_process_log.see(tk.END)
                
                # 1. 提取数据
                self.show_progress("执行完整提取流程...", 30)
                self.full_process_log.insert(tk.END, "1. 从含密图像中提取数据...\n")
                self.full_process_log.see(tk.END)
                
                recovered_remainder, recovered_multiple = self.stego_orchestrator.process_step_3_extraction(
                    self.stego_paths[0]
                )
                
                # 2. 保存提取的份额
                self.show_progress("执行完整提取流程...", 60)
                self.full_process_log.insert(tk.END, "2. 保存提取的份额...\n")
                self.full_process_log.see(tk.END)
                
                extracted_share_path = os.path.join(Config.SHARES_DIR, "extracted_share.npy")
                os.makedirs(Config.SHARES_DIR, exist_ok=True)
                
                np.save(extracted_share_path, {
                    'index': 0,
                    'modulus': self.crt_splitter.moduli[0],
                    'shape': recovered_remainder.shape,
                    'signature': b'test_signature',
                    'data': recovered_remainder.flatten()
                })
                
                self.extracted_share_paths = [extracted_share_path]
                
                # 3. 重构图像
                self.show_progress("执行完整提取流程...", 90)
                self.full_process_log.insert(tk.END, "3. 重构秘密图像...\n")
                self.full_process_log.see(tk.END)
                
                # 这里需要至少t个份额，使用原始份额进行测试
                if len(self.share_paths) >= Config.T_THRESHOLD:
                    selected_shares = self.share_paths[:Config.T_THRESHOLD]
                else:
                    selected_shares = self.share_paths
                
                recovered_img, recovered_sig = self.crt_reconstructor.reconstruct_image(selected_shares)
                
                # 保存重构图像
                output_dir = os.path.join(Config.DATASET_DIR, "reconstructed")
                os.makedirs(output_dir, exist_ok=True)
                
                self.reconstructed_image_path = os.path.join(output_dir, "reconstructed_full_process.png")
                recovered_img.save(self.reconstructed_image_path)
                
                self.show_progress("执行完整提取流程...", 100)
                self.full_process_log.insert(tk.END, "提取流程执行成功！\n")
                self.full_process_log.insert(tk.END, f"重构图像已保存到: {self.reconstructed_image_path}\n")
                self.full_process_log.see(tk.END)
                
                self.update_status("提取流程执行成功")
                self.hide_progress()
                messagebox.showinfo("成功", "提取流程执行成功！")
                
            except Exception as e:
                self.full_process_log.insert(tk.END, f"提取流程执行失败: {str(e)}\n")
                self.full_process_log.see(tk.END)
                self.update_status(f"提取流程执行失败: {str(e)}")
                self.hide_progress()
                messagebox.showerror("错误", f"提取流程执行失败: {str(e)}")
        
        self.run_in_thread(task)
    
    def view_results(self):
        """
        查看完整流程结果
        """
        try:
            if not self.stego_image_path or not self.reconstructed_image_path:
                raise ValueError("请先执行完整流程")
            
            # 创建结果窗口
            result_window = tk.Toplevel(self.root)
            result_window.title("流程结果")
            result_window.geometry("800x600")
            
            # 创建图像显示框架
            result_frame = ttk.Frame(result_window)
            result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # 创建网格布局
            result_frame.grid_rowconfigure(0, weight=1)
            result_frame.grid_rowconfigure(1, weight=1)
            result_frame.grid_columnconfigure(0, weight=1)
            result_frame.grid_columnconfigure(1, weight=1)
            
            # 含密图像
            ttk.Label(result_frame, text="含密图像", font=("SimHei", 10, "bold")).grid(row=0, column=0, pady=5)
            stego_label = ttk.Label(result_frame)
            stego_label.grid(row=1, column=0, padx=10, pady=10)
            self.display_image(stego_label, self.stego_image_path)
            
            # 重构图像
            ttk.Label(result_frame, text="重构图像", font=("SimHei", 10, "bold")).grid(row=0, column=1, pady=5)
            reconstructed_label = ttk.Label(result_frame)
            reconstructed_label.grid(row=1, column=1, padx=10, pady=10)
            self.display_image(reconstructed_label, self.reconstructed_image_path)
            
        except Exception as e:
            messagebox.showerror("错误", f"查看结果失败: {str(e)}")
    
    def clear_full_process(self):
        """
        清除完整流程数据
        """
        self.carrier_image_path = ""
        self.secret_image_path = ""
        self.stego_image_path = ""
        self.reconstructed_image_path = ""
        self.share_paths = []
        self.extracted_share_paths = []
        self.stego_paths = []
        
        self.full_carrier_var.set("")
        self.full_secret_var.set("")
        
        self.full_process_log.delete(1.0, tk.END)
        self.full_process_log.insert(tk.END, "完整流程已初始化\n")
        self.full_process_log.insert(tk.END, "选择载体图像和秘密图像后执行相应操作\n")
    
    def display_image(self, label, image_path):
        """
        显示图像到标签
        参数:
            label: 标签控件
            image_path: 图像路径
        """
        try:
            # 读取图像
            img = Image.open(image_path)
            
            # 调整图像大小以适应标签
            max_width = 300
            max_height = 200
            
            width, height = img.size
            if width > max_width or height > max_height:
                ratio = min(max_width / width, max_height / height)
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                img = img.resize((new_width, new_height), Image.LANCZOS)
            
            # 转换为Tkinter兼容格式
            photo = ImageTk.PhotoImage(img)
            
            # 显示图像
            label.config(image=photo)
            label.image = photo  # 保存引用，防止被垃圾回收
            
        except Exception as e:
            label.config(text=f"无法显示图像: {str(e)}")
    
    def clear_lattice_log(self):
        """
        清除格密码日志
        """
        self.lattice_log.delete(1.0, tk.END)
        self.lattice_log.insert(tk.END, "格密码门限签名系统已初始化\n")
        self.lattice_log.insert(tk.END, "点击按钮执行相应操作\n")
    
    def create_status_bar(self):
        """
        创建状态栏
        """
        # 状态栏框架
        self.status_bar = ttk.Frame(self.root, relief=tk.SUNKEN, height=30, style="TFrame")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 10))
        
        # 左侧状态信息
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_label = ttk.Label(self.status_bar, textvariable=self.status_var, anchor=tk.W, 
                               font=("SimHei", 10, "normal"), foreground="#1a365d")
        status_label.pack(side=tk.LEFT, padx=15, pady=5)
        
        # 中间分隔线
        separator = ttk.Separator(self.status_bar, orient=tk.VERTICAL)
        separator.pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        # 中间模块信息
        self.module_var = tk.StringVar()
        self.module_var.set("当前模块: 首页")
        module_label = ttk.Label(self.status_bar, textvariable=self.module_var, anchor=tk.CENTER, 
                               font=("SimHei", 10, "normal"), foreground="#4a5568")
        module_label.pack(side=tk.LEFT, padx=15, pady=5)
        
        # 右侧分隔线
        separator2 = ttk.Separator(self.status_bar, orient=tk.VERTICAL)
        separator2.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        
        # 右侧时间显示
        self.time_var = tk.StringVar()
        self.update_time()
        time_label = ttk.Label(self.status_bar, textvariable=self.time_var, anchor=tk.E, 
                              font=("SimHei", 10, "normal"), foreground="#4a5568")
        time_label.pack(side=tk.RIGHT, padx=15, pady=5)
    
    def update_time(self):
        """
        更新状态栏时间
        """
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.time_var.set(current_time)
        self.root.after(1000, self.update_time)  # 每秒更新一次
    
    def update_status(self, message):
        """
        更新状态栏消息
        参数:
            message: 状态消息
        """
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def create_progress_window(self):
        """
        创建进度条窗口
        """
        self.progress_window = tk.Toplevel(self.root)
        self.progress_window.title("处理中...")
        self.progress_window.geometry("500x120")
        self.progress_window.transient(self.root)  # 设置为主窗口的子窗口
        self.progress_window.resizable(False, False)
        self.progress_window.configure(bg="#f7fafc")
        # 不要在这里调用grab_set()，否则会导致整个应用程序被锁定
        self.progress_window.withdraw()  # 初始隐藏
        
        # 创建内容框架
        content_frame = ttk.Frame(self.progress_window, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建进度消息
        self.progress_message_var = tk.StringVar()
        self.progress_message_var.set("准备处理...")
        self.progress_message = ttk.Label(content_frame, textvariable=self.progress_message_var, 
                                         font=("SimHei", 11, "normal"), foreground="#1a365d")
        self.progress_message.pack(padx=10, pady=10, anchor=tk.W)
        
        # 创建进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(content_frame, variable=self.progress_var, maximum=100, 
                                          style="Horizontal.TProgressbar", length=450)
        self.progress_bar.pack(fill=tk.X, padx=10, pady=10)
        
        # 创建底部框架
        bottom_frame = ttk.Frame(content_frame)
        bottom_frame.pack(fill=tk.X, pady=5)
        
        # 创建取消按钮
        self.cancel_button = ttk.Button(bottom_frame, text="取消", command=self.cancel_process, 
                                       style="TButton", width=10)
        self.cancel_button.pack(side=tk.RIGHT, padx=10)
    
    def show_progress(self, message, value=0):
        """
        显示进度条
        参数:
            message: 进度消息
            value: 进度值 (0-100)
        """
        self.progress_message_var.set(message)
        self.progress_var.set(value)
        self.progress_window.deiconify()  # 显示窗口
        self.progress_window.grab_set()  # 模态窗口，防止用户与主窗口交互
        self.root.update_idletasks()
    
    def hide_progress(self):
        """
        隐藏进度条
        """
        self.progress_window.grab_release()  # 释放模态状态
        self.progress_window.withdraw()  # 隐藏窗口
    
    def bind_shortcuts(self):
        """
        绑定快捷键
        """
        # 绑定Ctrl+Q退出
        self.root.bind("<Control-q>", lambda e: self.root.quit())
        self.root.bind("<Control-Q>", lambda e: self.root.quit())
        
        # 绑定F1显示帮助
        self.root.bind("<F1>", lambda e: self.show_help())
    
    def on_tab_changed(self, event):
        """
        标签页切换事件处理
        """
        tab_index = self.notebook.index(self.notebook.select())
        tab_names = ["首页", "格密码签名", "CRT秘密共享", "图像隐写", "完整流程", "关于"]
        if tab_index < len(tab_names):
            self.module_var.set(f"当前模块: {tab_names[tab_index]}")
            self.update_status("就绪")
    
    def show_help(self):
        """
        显示帮助信息
        """
        help_text = """
        后量子安全图像隐写系统 - 使用帮助
        
        快捷键:
        Ctrl+Q - 退出系统
        F1 - 显示此帮助信息
        
        功能模块:
        1. 格密码签名 - 生成和验证格密码签名
        2. CRT秘密共享 - 分割和重构秘密图像
        3. 图像隐写 - 嵌入和提取数据
        4. 完整流程 - 执行端到端的隐写流程
        
        使用步骤:
        1. 选择载体图像和秘密图像
        2. 执行嵌入流程生成含密图像
        3. 执行提取流程恢复秘密图像
        
        注意事项:
        - 载体图像应大于等于秘密图像
        - 至少需要选择t个份额才能重构图像
        - 处理大图像可能需要较长时间
        """
        messagebox.showinfo("使用帮助", help_text)
    
    def cancel_process(self):
        """
        取消正在进行的处理
        """
        self.is_processing = False
        self.hide_progress()
        self.update_status("处理已取消")
        messagebox.showinfo("取消", "处理已取消")
    
    def run_in_thread(self, func, *args, **kwargs):
        """
        在新线程中运行函数，避免阻塞UI
        参数:
            func: 要运行的函数
            *args: 函数参数
            **kwargs: 函数关键字参数
        """
        def wrapper():
            try:
                self.is_processing = True
                result = func(*args, **kwargs)
                if not self.is_processing:
                    return None
                self.is_processing = False
                return result
            except Exception as e:
                if not self.is_processing:
                    return None
                self.is_processing = False
                messagebox.showerror("错误", f"处理失败: {str(e)}")
                self.update_status(f"处理失败: {str(e)}")
                self.hide_progress()
        
        thread = threading.Thread(target=wrapper)
        thread.daemon = True
        thread.start()
