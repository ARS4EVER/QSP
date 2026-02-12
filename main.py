# -*- coding: utf-8 -*-
"""
主应用程序入口文件
文件路径: main.py

仅包含程序入口逻辑，通过导入GUI模块启动应用程序。
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 导入现代化GUI模块
from GUI.app_modern import ModernApp


def main():
    """
    程序主入口函数
    """
    print("启动后量子安全图像隐写系统...")
    print("正在初始化现代化GUI界面...")
    
    # 创建现代化应用程序实例
    app = ModernApp()
    
    print("GUI界面初始化完成，启动主循环...")
    
    # 运行主循环
    app.mainloop()


if __name__ == "__main__":
    main()
