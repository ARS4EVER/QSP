# 抗量子去中心化资产保护系统 (QSP)

## 目录

1. [项目简介](#项目简介)
2. [系统概述](#系统概述)
3. [系统架构](#系统架构)
4. [项目结构](#项目结构)
5. [核心模块详解](#核心模块详解)
6. [快速开始](#快速开始)
7. [测试覆盖](#测试覆盖)
8. [安全特性](#安全特性)
9. [技术依赖](#技术依赖)
10. [环境准备](#环境准备)
11. [安装与启动](#安装与启动)
12. [核心功能使用](#核心功能使用)
13. [常见问题](#常见问题)

---

## 项目简介

QSP是一个基于格密码学的综合性安全系统，专注于提供抗量子计算攻击的加密通信、身份认证和资产保护功能。该系统利用格密码的抗量子特性，结合P2P网络、可靠UDP和Shamir秘密共享,项目由暨南大学杨昊文、熊逸航完成。


## 贡献者

| 姓名/昵称 | GitHub ID | 贡献内容 | 联系方式 |
|----------|-----------|---------|---------|
| 熊逸航 | ARS4EVER | 代码编写、测试维护、漏洞修复 | 2568910086@qq.com |
| 杨昊文 | amonadam | 项目架构、代码编写、测试维护 | 3032875322@qq.com |


### 核心特性

1. **纯正抗量子基因** - 100% 遵守 NIST FIPS 203 (Kyber512) 和 FIPS 204 (Dilithium2) 标准
2. **绝对安全握手** - 基于 `Dilithium Sign(Kyber_Ciphertext)` 混合架构，完美抵御中间人攻击 (MITM)
3. **极简业务流** - `REQ-RESP` 单轮交互，配合 JSON 序列化和 AES-GCM，实现高吞吐量
4. **无缝 Shamir 门限** - 数据容灾由业务层 `Splitter/Reconstructor` 接管，密码层与业务层完全解耦
5. **本地金库加密** - 基于 PBKDF2HMAC 和 AES-256-GCM 的透明加密，防范物理设备被攻破
6. **邀请码瘦身** - 采用公钥指纹验证机制，大幅减少邀请码大小，提升传输效率
7. **NAT 穿透** - 支持 UDP 打洞和心跳保活，实现真正的去中心化 P2P 连接
8. **可靠 UDP** - 集成 SACK 和拥塞控制，提供接近 TCP 的可靠性和 UDP 的低延迟

---

## 系统概述

抗量子去中心化资产保护系统（QSP）提供以下核心功能：

- ✅ **抗量子加密**：使用 NIST 标准的 Kyber 和 Dilithium 算法
- ✅ **P2P 网络通信**：支持 NAT 穿透和 UDP 打洞
- ✅ **Shamir 秘密共享**：将文件分割成多份，需要指定数量的份额才能恢复
- ✅ **本地金库加密**：使用 AES-256-GCM 保护本地数据

---

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                      业务层                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ BackupManager│  │ RecoveryManager │  │ AppRouter      │  │
│  │              │  │              │  │                │  │
│  └──────────────┘  └──────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      应用层                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ AppMessage   │  │ AppProtocol  │  │ UIBridge       │  │
│  │              │  │              │  │                │  │
│  └──────────────┘  └──────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      安全通道                                │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ SecureLink: SecureChannel + RUDP + Heartbeat        │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      密码学层                                │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────┐  │
│  │ Lattice-   │ │ KeyGen    │ │ Dilithium- │ │Kyber- │  │
│  │ Wrapper    │ │           │ │ Signer     │ │KEM    │  │
│  └────────────┘ └────────────┘ └────────────┘ └──────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      配置层                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ config.py: SigParams, KEMParams, ThresholdParams    │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 项目结构

```
QSP1/
├── GUI/
│   └── main_window.py        # 现代化 GUI 界面
├── data/
│   ├── keys/                  # 身份密钥
│   │   └── node_identity.json
│   ├── shares/                # 资产份额和清单
│   │   ├── {哈希前8位}_manifest.json
│   │   └── {文件哈希}_share_X.dat
│   └── restored/              # 恢复的资产
│       └── recovered_{文件名}
├── src/
│   ├── app/                 # 应用层 (Phase 10)
│   │   ├── app_protocol.py     # 应用层消息协议
│   │   ├── app_router.py       # 应用层消息路由
│   │   ├── backup_manager.py   # 资产备份管理器
│   │   ├── recovery_manager.py # 资产恢复管理器
│   │   ├── ui_bridge.py         # UI 桥接器
│   │   └── vault_crypto.py     # 本地金库加密引擎
│   ├── crypto_lattice/     # 格密码模块 (Phase 1)
│   │   ├── wrapper.py         # 统一适配器 (ML-DSA + ML-KEM)
│   │   ├── keygen.py         # 密钥生成
│   │   ├── signer.py         # 标准签名器 (DilithiumSigner)
│   │   └── encryptor.py      # 密钥封装 (KyberKEM)
│   ├── network/             # 网络通信模块 (Phase 2)
│   │   ├── secure_channel.py   # 安全通道
│   │   ├── secure_link.py      # 安全链接 (含心跳)
│   │   ├── p2p_manager.py     # P2P 管理
│   │   ├── rudp.py            # 可靠 UDP
│   │   ├── protocol.py        # 通信协议
│   │   └── congestion.py      # 拥塞控制
│   ├── secret_sharing/      # 秘密共享模块
│   │   ├── splitter.py         # Shamir 分割器
│   │   └── reconstructor.py   # Shamir 重构器
│   ├── utils/               # 工具函数
│   └── config.py            # 全局配置
├── tests/                   # 测试代码目录
├── main.py                  # 主程序入口
├── requirements.txt         # 依赖包列表
└── README.md                # 本文档
```

---

## 核心模块详解

### 1. 应用层 (`src/app/`)

现代化的业务逻辑实现：

- **vault_crypto.py** - 本地金库加密引擎
  - `VaultCrypto._derive_key()` - 基于 PBKDF2HMAC 的密钥派生
  - `VaultCrypto.encrypt_chunk()` / `decrypt_chunk()` - AES-256-GCM 块级加密/解密
  - 防范物理设备被攻破导致的数据泄露

- **backup_manager.py** - 资产备份管理器
  - `BackupManager.execute_backup()` - 执行资产备份和网络分发
  - `BackupManager._save_share_locally()` - 本地加密存储份额
  - 支持 P2P 网络传输和断点续传

- **recovery_manager.py** - 资产恢复管理器
  - `RecoveryManager.execute_recovery()` - 执行资产恢复和网络寻呼
  - `RecoveryManager._try_reconstruct_streaming()` - 流式重构资产
  - 支持网络乱序分块接收和断点续传

- **app_protocol.py** - 应用层消息协议
  - `AppMessage.pack()` / `unpack()` - 消息序列化和反序列化
  - 支持 SHARE_PUSH、PULL_REQ、PULL_RESP 等消息类型

- **app_router.py** - 应用层消息路由
  - `AppRouter.register_handler()` - 注册消息处理器
  - `AppRouter.dispatch_network_data()` - 分发网络数据
  - 支持线程安全的 UI 更新

- **ui_bridge.py** - UI 桥接器
  - `UIBridge.run_in_main_thread()` - 在主线程中运行 UI 更新
  - `UIBridge.safe_update_progress()` - 安全更新进度条
  - 解决多线程 UI 更新问题

### 2. 密码学层 (`src/crypto_lattice/`)

基于 NIST 标准的后量子密码学实现：

- **wrapper.py** - 统一适配器
  - `LatticeWrapper.generate_signing_keypair()` - 生成 Dilithium 签名密钥对
  - `LatticeWrapper.sign_message()` / `verify_signature()` - 标准签名/验签
  - `LatticeWrapper.kem_keygen()` / `encapsulate()` / `decapsulate()` - Kyber512 密钥交换

- **keygen.py** - 密钥生成工具
  - `KeyGen.generate_keys()` - 生成密钥对
  - `KeyGen.save_keys()` / `load_keys()` - 密钥持久化

- **signer.py** - 标准签名器
  - `DilithiumSigner.sign()` - 使用私钥签名
  - `DilithiumSigner.verify()` - 使用公钥验签

- **encryptor.py** - 密钥封装
  - `KyberKEM.generate_keypair()` - 生成 KEM 密钥对
  - `KyberKEM.encapsulate()` / `decapsulate()` - 密钥封装/解封装

### 3. 网络通信层 (`src/network/`)

端到端加密通信：

- **secure_link.py** - 安全链接
  - 集成 SecureChannel、RUDP 和心跳保活
  - 支持多路复用和 NAT 穿透
  - 采用公钥指纹验证机制，提升安全性和效率

- **secure_channel.py** - 安全通道
  - 集成 Kyber512 密钥交换
  - 集成 Dilithium2 身份认证
  - 使用 AES-256-GCM 加密业务数据
  - 支持中间人攻击拦截

- **p2p_manager.py** - P2P 节点管理
  - `P2PNode.connect_via_invite()` - 通过邀请码连接
  - `P2PNode.generate_invite_code()` - 生成轻量化邀请码
  - 支持 UDP 打洞和 NAT 穿透

- **rudp.py** - 可靠 UDP 传输
  - `RUDPConnection.receive_data()` - 接收数据并生成 SACK
  - `RUDPConnection.handle_sack()` - 处理 SACK 并触发重传
  - 支持乱序到达和快速重传

- **protocol.py** - 二进制通信协议
  - `QSPProtocol.pack()` / `unpack()` - 数据包封装和解析
  - 支持 KEEPALIVE、HOLEPUNCH 等消息类型

- **congestion.py** - 延迟梯度拥塞控制
  - `HybridCongestionControl.on_ack()` - 处理 ACK 并调整拥塞窗口
  - 基于延迟梯度和丢包率的混合拥塞控制

### 4. 秘密共享 (`src/secret_sharing/`)

基于 Shamir's Secret Sharing 的门限容灾：

- **splitter.py** - 秘密分割
  - `SecretSplitter.split_secret()` - 将秘密分割为 n 个份额
  - 支持 GF(256) 查表加速

- **reconstructor.py** - 秘密重构
  - `SecretReconstructor.reconstruct()` - 使用 t 个份额重构秘密
  - 支持流式重构和大文件处理

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
python -m unittest tests.test_wrapper tests.test_keygen_phase2 tests.test_signer_phase2 tests.test_secure_channel_phase2 tests.test_vault_encryption_phase10 tests.test_holepunch_phase5 tests.test_large_file_streaming tests.test_integration_final -v
```

### 3. 运行系统

```bash
python main.py
```

---

## 测试覆盖

| 测试模块 | 测试内容 |
|----------|----------|
| test_wrapper.py | ML-DSA 签名/验签、ML-KEM 封装/解封装 |
| test_keygen_phase2.py | 标准密钥生成与存储 |
| test_signer_phase2.py | 标准 Dilithium 签名器 |
| test_encryptor_phase2.py | Kyber KEM 密钥交换 |
| test_config_phase2.py | 配置参数验证 |
| test_secure_channel_phase2.py | 安全通道握手、AES-GCM 加密 |
| test_holepunch_phase5.py | NAT 穿透和 UDP 打洞 |
| test_p2p_multiplexing.py | P2P 多路复用 |
| test_rudp_sack.py | 可靠 UDP 和 SACK 机制 |
| test_congestion_phase4.py | 延迟梯度拥塞控制 |
| test_secure_link_phase6.py | 安全链接和心跳保活 |
| test_keepalive_phase8.py | NAT 保活机制 |
| test_vault_encryption_phase10.py | 本地金库加密和防篡改 |
| test_large_file_streaming.py | 大文件流式切分和重构 |
| test_recovery_streaming_phase7.py | 网络乱序分块接收和断点续传 |
| test_app_protocol.py | 应用层消息协议 |
| test_app_router.py | 应用层消息路由 |
| test_integration_final.py | 端到端集成测试 |

**所有测试全部通过** ✅

---

## 安全特性

1. **抗量子安全**
   - NIST FIPS 203 ML-KEM-512 (Kyber512)
   - NIST FIPS 204 ML-DSA-44 (Dilithium2)
   
2. **身份认证**
   - Dilithium 标准签名
   - 公钥指纹验证
   - 中间人攻击拦截
   
3. **数据加密**
   - AES-256-GCM
   - 前向安全性
   - 本地金库加密
   
4. **门限容灾**
   - Shamir Secret Sharing
   - (t, n) 门限方案
   - 流式重构

5. **网络安全**
   - UDP 打洞和 NAT 穿透
   - 可靠 UDP 与 SACK
   - 延迟梯度拥塞控制
   - 心跳保活机制

---

## 技术依赖

- Python 3.9+
- dilithium-py
- kyber-py
- cryptography
- numpy
- customtkinter
- pillow

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

## 核心功能使用

### 功能一：身份与网络

#### 1.1 查看和复制本机邀请码

1. 启动应用后，默认显示"身份与网络"标签页
2. 顶部会显示你的**本机专属邀请码**
3. 点击"复制邀请码"按钮，将邀请码复制到剪贴板
4. 将此邀请码发送给其他需要连接的节点

**邀请码的作用**：
- 包含你的公钥指纹和网络坐标
- 其他节点通过此邀请码可以安全地连接到你

#### 1.2 连接远端节点

1. 获取其他节点的邀请码
2. 在"连接远端节点"输入框中粘贴邀请码
3. 点击"发起UDP穿透与安全握手"按钮
4. 等待连接建立（状态会显示"安全链接建立"）

**连接过程**：
- 系统会自动执行 UDP 打洞（NAT 穿透）
- 使用 Kyber 密钥交换建立加密通道
- 使用 Dilithium 签名进行身份认证

---

### 功能二：资产备份

#### 2.1 备份流程

1. 点击左侧边栏的"资产备份"标签
2. 点击"选择待保护机密文件"按钮
3. 在弹出的文件选择框中选择要保护的文件
4. 设置参数：
   - **总节点数 (N)**：将文件分割成多少份（默认 5）
   - **恢复门限 (T)**：需要多少份才能恢复文件（默认 3）
   - ⚠️ 注意：必须满足 `1 < T <= N`
5. 点击"执行核心资产分割与加密"按钮
6. 等待进度条完成

#### 2.2 备份完成后

- 系统会显示成功提示，包含**元数据清单文件的保存位置**
- 请妥善保管这个清单文件（`.json` 格式），恢复时需要用到
- 文件份额会通过 P2P 网络分发到已连接的节点

**备份原理**：
1. 文件被加密（AES-256-GCM）
2. 使用 Shamir 秘密共享算法分割成 N 份
3. 份额加密存储并分发到网络
4. 需要至少 T 份才能重构原文件

---

### 功能三：资产恢复

#### 3.1 恢复流程

1. 点击左侧边栏的"资产恢复"标签
2. 点击"导入资产清单 (Manifest)"按钮
3. 选择备份时生成的清单文件（`.json`）
4. 点击"执行身份签名验证与资产重构"按钮
5. 等待进度条完成

#### 3.2 恢复过程

- 系统会向 P2P 网络广播拉取请求
- 收集足够的份额（>= T）
- 验证每个份额的身份签名
- 使用 Shamir 算法重构原始文件
- 恢复完成后会显示文件保存位置

---

## 常见问题

### Q1: pip 安装依赖时出现 "Fatal error in launcher" 错误？

**A**: 使用 `python -m pip` 代替 `pip`，例如：
```bash
python -m pip install -r requirements.txt
```

如果想永久修复，可以重新安装 pip：
```bash
python -m pip install --upgrade --force-reinstall pip
```

### Q2: 忘记本地金库密码怎么办？

**A**: 很遗憾，本地金库密码无法找回。你需要：
1. 删除 `data/keys/` 目录下的密钥文件
2. 删除 `data/shares/` 目录下的份额文件
3. 重新启动应用，设置新密码
4. ⚠️ 注意：之前本地存储的数据将无法恢复

### Q3: 连接其他节点失败？

**A**: 请检查：
1. 对方节点是否在线
2. 邀请码是否正确（完整复制，不要有多余空格）
3. 网络是否允许 UDP 通信（某些防火墙可能阻止）
4. 双方是否都在同一版本的系统上

### Q4: 恢复时收集不到足够的份额？

**A**: 可能原因：
1. 存储份额的节点不在线
2. 网络连接问题
3. 检查清单文件是否正确
4. 尝试等待更长时间，或联系更多节点上线

### Q5: 支持哪些文件类型？

**A**: 系统支持任何类型的文件：
- 文档（.docx, .pdf, .txt 等）
- 图片（.jpg, .png, .gif 等）
- 视频和音频文件
- 压缩包（.zip, .rar 等）
- 任意二进制文件

文件大小建议：虽然系统支持大文件，但建议单个文件不超过 1GB 以获得最佳性能。

### Q6: 如何确保安全性？

**A**: 系统通过多层加密保护：
1. **传输层**：Kyber 密钥交换 + AES-256-GCM 加密
2. **身份认证**：Dilithium 数字签名
3. **存储层**：本地金库 AES-256-GCM 加密
4. **容灾层**：Shamir 秘密共享，即使部分节点丢失也能恢复

### Q7: 可以在多台设备上使用同一身份吗？

**A**: 不建议。每个节点应该有独立的身份：
- 身份文件存储在 `data/keys/node_identity.json`
- 如果需要在多台设备使用，可以复制此文件（但存在安全风险）
- 更好的方式是让每台设备生成独立身份，然后互相连接

---

## 技术支持

如遇到其他问题，请检查：
1. Python 版本是否符合要求
2. 所有依赖是否正确安装
3. 网络连接是否正常
4. 防火墙设置是否允许 UDP 通信

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

