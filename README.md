<div align="center">
  <img src="./image/logo.png" alt="QSP Logo" width="600"/>
  <h1 align="center">QSP</h1>
  <h3 align="center">基于PQC的抗量子秘密文件共享与传输系统</h3>
</div>

<!-- PROJECT SHIELDS -->

<p align="center">
  <a href="https://github.com/ARS4EVER/QSP/graphs/contributors">
    <img alt="GitHub License" src="https://img.shields.io/github/contributors/ARS4EVER/QSP.svg?style=">
  </a>
  <a href="https://github.com/ARS4EVER/QSP/network/members">
    <img alt="GitHub release" src="https://img.shields.io/github/forks/ARS4EVER/QSP.svg?style=">        
  </a>
  <a href="https://github.com/ARS4EVER/QSP/stargazers">
    <img alt="Tech Report" src="https://img.shields.io/github/stars/ARS4EVER/QSP.svg?style">
  </a>
  <a href="https://img.shields.io/github/issues/QSP.svg">
    <img alt="Demo" src="https://img.shields.io/github/issues/ARS4EVER/QSP.svg?style">
  </a>
</p>

<p align="center">
  <br />
  <a href="https://github.com/ARS4EVER/QSP"><strong>探索本项目的文档 »</strong></a>
  <br />
  <br />
  <a href="https://github.com/ARS4EVER/QSP/issues">报告Bug</a>
  ·
  <a href="https://github.com/ARS4EVER/QSP/issues">提出新特性</a> 
</p>

## 目录

1. [项目简介](#项目简介)
   - [功能特性](#功能特性)
   - [项目成员](#项目成员)
   - [整体框架](#整体框架)
   - [项目结构](#项目结构)
3. [快速开始](#快速开始)
4. [环境准备](#环境准备)
5. [安装与启动](#安装与启动)
6. [系统具体使用流程](#系统具体使用流程)
7. [附录：配置参数说明](#附录配置参数说明)

---

## 项目简介

QSP是一个基于格密码学的综合性安全系统，专注于提供抗量子计算攻击的加密通信、身份认证和秘密文件共享与传输功能。本系统利用格密码的抗量子特性，结合P2P网络、可靠UDP和Shamir秘密共享,项目由暨南大学杨昊文、熊逸航完成。

### 功能特性

1. 当前的加密通信方式大多采用传统的非对称加密算法，比如RSA,ECC等，这些算法在量子计算下存在被破解的风险，本系统严格采用 NIST 最新的 ML-KEM-512 与 ML-DSA-44 标准构建了 1.5-RTT 的安全握手协议实现后量子时代的加密通信，并借此实现了多方密钥安全协商。
2. 传统的云存储服务高度依赖中心化服务器，极易遭遇单点故障，本系统通过引入 Shamir 秘密共享 (t, n) 门限算法结合本地 AES-256-GCM 加密，将机密资产打散并安全分发至 P2P 网络，实现了去中心化的秘密文件存储的安全性。
3. 为解决经典的Shamir秘密共享在处理大文件时，数据量过大导致传输效率低的问题，本系统引入基于伽罗瓦域 GF(256) 的查表法进行深度优化，将乘除法时间复杂度降至 O(1)，用空间换时间，成功提高了大文件的传输与重构效率，
4. 为解决复杂 NAT 网络节点直连困难、普通 UDP 难以保障弱网下大文件可靠传输以及易受重放攻击等难点，本系统通过采用基于 STUN 的 UDP 打洞技术，带有 SACK 与拥塞控制机制的 RUDP 协议，并引入高熵挑战-应答机制，在保证极低延迟的同时实现了可靠传输。


### 项目成员

| 姓名/昵称 | GitHub ID | 贡献内容 | 联系方式 |
|----------|-----------|---------|---------|
| 熊逸航 | ARS4EVER | 代码编写、测试维护、漏洞修复 | 2568910086@qq.com |
| 杨昊文 | amonadam | 项目架构、代码编写、测试维护 | 3032875322@qq.com |
### 贡献者
<!-- readme: collaborators,contributors -start -->
<table>
	<tbody>
		<tr>
            <td align="center">
                <a href="https://github.com/StarMike-code">
                    <img src="https://avatars.githubusercontent.com/u/182243318?v=4" width="50;" alt="StarMike-code"/>
                    <br />
                    <sub><b>StarMike-code</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/ARS4EVER">
                    <img src="https://avatars.githubusercontent.com/u/164615540?v=4" width="50;" alt="ARS4EVER"/>
                    <br />
                    <sub><b>ARS4EVER</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/amonadam">
                    <img src="https://avatars.githubusercontent.com/u/164615153?v=4" width="50;" alt="amonadam"/>
                    <br />
                    <sub><b>amonadam</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/Wheeler14H">
                    <img src="https://avatars.githubusercontent.com/u/260823371?v=4" width="50;" alt="Wheeler14H"/>
                    <br />
                    <sub><b>Wheeler14H</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/Martin8edg">
                    <img src="https://avatars.githubusercontent.com/u/286713677?v=4" width="50;" alt="Martin8edg"/>
                    <br />
                    <sub><b>Martin8edg</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/nicolosshit">
                    <img src="https://avatars.githubusercontent.com/u/269751672?v=4" width="50;" alt="nicolosshit"/>
                    <br />
                    <sub><b>nicolosshit</b></sub>
                </a>
            </td>
		</tr>
		<tr>
            <td align="center">
                <a href="https://github.com/IsAlPhA77">
                    <img src="https://avatars.githubusercontent.com/u/153442774?v=4" width="50;" alt="IsAlPhA77"/>
                    <br />
                    <sub><b>isalpha</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/AlphaSheeran">
                    <img src="https://avatars.githubusercontent.com/u/144607354?v=4" width="50;" alt="AlphaSheeran"/>
                    <br />
                    <sub><b>AlphaSheeran</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/csj-TJ">
                    <img src="https://avatars.githubusercontent.com/u/180985451?v=4" width="50;" alt="csj-TJ"/>
                    <br />
                    <sub><b>Cao Shaojie</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/Jiky-York">
                    <img src="https://avatars.githubusercontent.com/u/191967241?v=4" width="50;" alt="Jiky-York"/>
                    <br />
                    <sub><b>Jiky-York</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/kan-ner">
                    <img src="https://avatars.githubusercontent.com/u/203961430?v=4" width="50;" alt="kan-ner"/>
                    <br />
                    <sub><b>kan-ner</b></sub>
                </a>
            </td>
		</tr>
	<tbody>
</table>
<!-- readme: collaborators,contributors -end -->



### 整体框架



![framework](./image/framework.png)



---

### 项目结构

```
QSP-main/
├── GUI/
│   └── main_window.py        # 现代化 GUI 界面
├── data/
│   ├── keys/                  # 身份密钥 (AES-256-GCM 加密存储)
│   │   ├── node_identity.dat  # 加密的节点身份文件
│   │   ├── .vault_salt        # 密钥派生盐值
│   │   └── .vault_verifier    # 密码验证器
│   ├── shares/                # 资产份额和清单
│   │   ├── {文件哈希}_share_X.dat
│   │   └── .qsp_identity.pem  # 节点身份证书
│   └── restored/              # 恢复的资产
│       └── recovered_{文件名}
├── image/                    # 图像资源
│   └── logo.jpg              # 项目 Logo
├── src/
│   ├── app/                  # 应用层 (Phase 10)
│   │   ├── app_protocol.py     # 应用层消息协议
│   │   ├── app_router.py       # 应用层消息路由
│   │   ├── backup_manager.py   # 资产备份管理器
│   │   ├── recovery_manager.py # 资产恢复管理器
│   │   ├── ui_bridge.py        # UI 桥接器
│   │   └── vault_crypto.py     # 本地金库加密引擎
│   ├── core/                  # 核心协议层
│   │   ├── challenge_auth.py   # 挑战认证协议
│   │   ├── messages.py         # 协议消息定义
│   │   ├── recovery_host.py    # 恢复主机逻辑
│   │   └── recovery_participant.py # 恢复参与者逻辑
│   ├── crypto_lattice/        # 格密码模块 (Phase 1)
│   │   ├── wrapper.py         # 统一适配器 (ML-DSA + ML-KEM)
│   │   ├── keygen.py          # 密钥生成
│   │   ├── signer.py          # 标准签名器 (DilithiumSigner)
│   │   └── encryptor.py       # 密钥封装 (KyberKEM)
│   ├── network/              # 网络通信模块 (Phase 2)
│   │   ├── secure_channel.py   # 安全通道
│   │   ├── secure_link.py      # 安全链接 (含心跳)
│   │   ├── p2p_manager.py     # P2P 管理
│   │   ├── rudp.py            # 可靠 UDP
│   │   ├── protocol.py        # 通信协议
│   │   └── congestion.py      # 拥塞控制
│   ├── secret_sharing/       # 秘密共享模块
│   │   ├── splitter.py         # Shamir 分割器
│   │   ├── reconstructor.py   # Shamir 重构器
│   │   └── gf256.py           # GF(256) 有限域运算
│   ├── utils/                # 工具函数
│   │   ├── data_handler.py     # 数据处理工具
│   │   └── logger.py          # 日志工具
│   └── config.py             # 全局配置
├── tests/                    # 测试代码目录
├── main.py                   # 主程序入口
├── requirements.txt          # 依赖包列表
└── README.md                 # 本文档
```

---

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 运行测试

```bash
# 运行所有核心测试
python -m unittest discover tests -v

# 运行特定模块测试
python -m unittest tests.test_wrapper tests.test_keygen_phase2 tests.test_signer_phase2 tests.test_encryptor_phase2 tests.test_config_phase2 tests.test_secure_channel_phase2 tests.test_holepunch_phase5 tests.test_p2p_multiplexing tests.test_rudp_sack tests.test_congestion_phase4 tests.test_secure_link_phase6 tests.test_keepalive_phase8 tests.test_vault_encryption_phase10 tests.test_large_file_streaming tests.test_recovery_streaming_phase7 tests.test_app_protocol tests.test_app_protocol_phase2 tests.test_app_router tests.test_c10_two_way_auth tests.test_c4_c9_security tests.test_c8_challenge_auth tests.test_c8_clock_sync_replay tests.test_c8_phases3_4 tests.test_c9_typo_detection tests.test_ui_sync_phase5 tests.test_integration_final -v
```

### 3. 运行系统

```bash
python main.py
```

---



## 环境准备

### 系统要求

- **操作系统**：Windows / macOS / Linux
- **Python 版本**：3.9 或更高
- **网络**：需要互联网连接（用于 P2P 通信）

### 检查 Python 版本

打开终端/命令提示符，运行：

```bash
python --version
```

确保显示 Python 3.9+。

---

## 安装与启动

### 第一步：安装依赖

在项目目录下运行：

```bash
pip install -r requirements.txt
```

如果遇到 pip 启动器错误（如 "Fatal error in launcher"），使用：

```bash
python -m pip install -r requirements.txt
```

### 第二步：启动应用

运行主程序：

```bash
python main.py
```

### 第三步：设置本地金库密码

启动后，会弹出一个对话框，要求输入**本地金库主密码**：

- 这个密码用于加密本地存储的敏感数据
- 请牢记此密码！（如果忘记，本地数据将无法恢复）
- 如果不输入，系统会使用默认密码（不推荐）

---



## 系统具体使用流程



![framework](./image/framework_flow.png)



<div align="center">
  <blockquote>
    <strong>⚠️ 提示</strong><br>
    若有项目功能方面或运行问题，请查阅 <strong><a href="./Function description.md"><code>Function description.md</code></a></strong>
  </blockquote>
</div>
---


## 附录：配置参数说明

如需调整高级参数，可编辑 `src/config.py`：

| 参数类 | 参数 | 说明 | 默认值 |
|--------|------|------|--------|
| ThresholdParams | n_participants | 默认总节点数 | 5 |
| ThresholdParams | t | 默认恢复门限 | 3 |
| NetworkParams | MTU | 网络最大传输单元 | 1400 |
| NetworkParams | HANDSHAKE_TIMEOUT | 握手超时（秒） | 5.0 |
| NetworkParams | RTO_INITIAL | 重传超时初始值（秒） | 0.2 |

---


### 欢迎任何形式的贡献！

1. **提交 Bug 报告** - 发现问题请提交 Issue
2. **提交功能建议** - 有好的想法欢迎讨论
3. **提交代码** - 修复 Bug 或添加新功能
4. **改进文档** - 帮助完善使用文档
5. **推广宣传** - 分享给更多人使用
   
**欢迎提出改进意见** ✨
