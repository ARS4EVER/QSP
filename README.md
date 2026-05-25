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
   - [项目成员](#项目成员)
   - [功能特性](#功能特性)
   - [整体框架](#整体框架)
   - [项目结构](#项目结构)
2. [快速开始](#快速开始)
3. [环境准备](#环境准备)
4. [安装与启动](#安装与启动)
5. [核心功能描述](#核心功能描述)
6. [系统具体使用流程](#系统具体使用流程)
7. [常见问题](#常见问题)
8. [技术支持](#技术支持)
9. [附录：配置参数说明](#附录配置参数说明)

---

## 项目简介

QSP是一个基于格密码学的综合性安全系统，专注于提供抗量子计算攻击的加密通信、身份认证和秘密文件共享与传输功能。本系统利用格密码的抗量子特性，结合P2P网络、可靠UDP和Shamir秘密共享,项目由暨南大学杨昊文、熊逸航完成。


### 项目成员

| 姓名/昵称 | GitHub ID | 贡献内容 | 联系方式 |
|----------|-----------|---------|---------|
| 熊逸航 | ARS4EVER | 代码编写、测试维护、漏洞修复 | 2568910086@qq.com |
| 杨昊文 | amonadam | 项目架构、代码编写、测试维护 | 3032875322@qq.com |


### 功能特性

1. 当前的加密通信方式大多采用传统的非对称加密算法，比如RSA,ECC等，这些算法在量子计算下存在被破解的风险，本系统严格采用 NIST 最新的 ML-KEM-512 与 ML-DSA-44 标准构建了 1.5-RTT 的安全握手协议实现后量子时代的加密通信，并借此实现了多方密钥安全协商。
2. 传统的云存储服务高度依赖中心化服务器，极易遭遇单点故障，本系统通过引入 Shamir 秘密共享 (t, n) 门限算法结合本地 AES-256-GCM 加密，将机密资产打散并安全分发至 P2P 网络，实现了去中心化的秘密文件存储的安全性。
3. 为解决经典的Shamir秘密共享在处理大文件时，数据量过大导致传输效率低的问题，本系统引入基于伽罗瓦域 GF(256) 的查表法进行深度优化，将乘除法时间复杂度降至 O(1)，用空间换时间，成功提高了大文件的传输与重构效率，
4. 为解决复杂 NAT 网络节点直连困难、普通 UDP 难以保障弱网下大文件可靠传输以及易受重放攻击等难点，本系统通过采用基于 STUN 的 UDP 打洞技术，带有 SACK 与拥塞控制机制的 RUDP 协议，并引入高熵挑战-应答机制，在保证极低延迟的同时实现了可靠传输。

---

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

## 核心功能描述

### 功能一：身份管理与身份认证

#### 1.1 抗量子身份生成与验证

系统采用 **NIST FIPS 204 ML-DSA-44 (Dilithium)** 数字签名算法实现身份认证：

- **身份生成**：基于格密码学的后量子签名密钥对，公钥大小 1312 字节，私钥 2528 字节
- **身份验证**：采用公钥指纹验证机制，有效缩小证书体积，提升验证效率
- **挑战-响应协议**：实现双向认证流程，防止中间人攻击（MITM）
- **身份存储**：通过 PBKDF2HMAC-SHA256 密钥派生，结合 AES-256-GCM 加密本地身份凭证

**技术特点**：
- 基于模块格上的短整数解（SIS）问题，抗量子计算攻击
- 签名大小约 2420 字节，安全强度等价于 AES-128
- 支持确定性与概率性签名生成
- 本地身份文件加密存储于 [data/keys/node_identity.dat](data/keys/node_identity.dat)

#### 1.2 邀请码机制与网络发现

采用创新的 **公钥指纹 + 网络坐标** 邀请码机制：

- **邀请码结构**：包含节点 ID、公钥哈希、公网 IP 和端口信息
- **安全发现**：通过 STUN 服务器获取公网坐标，支持 IPv4/IPv6 双栈
- **身份验证**：建立连接前验证 Dilithium 签名，确保节点身份真实性
- **轻量传输**：邀请码体积压缩，便于在多种渠道传输

### 功能二：抗量子安全通信

#### 2.1 ML-KEM-512 密钥封装机制

通信通道建立采用 **NIST FIPS 203 ML-KEM-512 (Kyber)** 密钥封装算法：

- **密钥交换**：Kyber512 封装机制，公钥 800 字节，密文 768 字节
- **前向保密**：每次会话生成新的密钥材料，确保历史通信安全
- **完美前向保密**：长期密钥泄露不影响已建立会话的安全性
- **实现细节**：模块格上的学习带误差（MLWE）问题提供量子安全保障

#### 2.2 AES-256-GCM 安全通道

应用层数据传输采用认证加密算法：

- **加密算法**：AES-256-GCM 提供机密性、完整性和认证性
- **认证标签**：128 位认证标签，防止消息篡改
- **随机 Nonce**：96 位 Nonce，确保密文不可预测性
- **数据分片**：大文件分片传输，提高传输可靠性

#### 2.3 可靠 UDP (RUDP) 传输协议

自定义传输层协议实现可靠数据传输：

- **选择性确认 (SACK)**：基于 SACK 机制的重传策略，减少冗余数据传输
- **延迟梯度拥塞控制**：Hybrid 混合拥塞控制算法，结合延迟梯度与丢包率
- **心跳保活**：周期性心跳检测，维护连接状态
- **乱序重组**：支持数据包乱序到达与重组

**性能指标**：
- 支持最大 1400 字节 MTU
- 拥塞窗口动态调整，适应网络变化
- 丢包率小于 0.1% 时吞吐量接近 TCP

### 功能三：分布式秘密共享与数据容灾

#### 3.1 Shamir (t, n) 门限方案

数据容灾基于 **Shamir's Secret Sharing** 算法：

- **数学基础**：GF(256) 有限域上的多项式插值
- **门限参数**：(t, n) 方案，t 为恢复门限，n 为参与者总数
- **查表加速**：预计算 GF(256) 乘法/加法表，提升性能 10 倍以上
- **信息论安全**：少于 t 个份额无法获取任何明文信息

#### 3.2 分布式备份流程

完整的备份流程包含以下步骤：

1. **文件加密**：首先使用 AES-256-GCM 加密源文件
2. **秘密分割**：将加密后的文件分割为 n 个份额
3. **份额签名**：每个份额使用 Dilithium 私钥签名，确保完整性
4. **分发存储**：通过 P2P 网络将份额分发至已连接节点
5. **清单生成**：生成包含元数据的清单文件，用于恢复

**安全特性**：
- 每个份额独立加密存储
- 支持任意大小文件的流式处理
- 进度实时反馈与断点续传

#### 3.3 多方恢复机制

数据恢复流程实现多方协同：

1. **清单导入**：读取元数据清单，确定所需份额数量
2. **网络寻呼**：向 P2P 网络广播份额请求
3. **份额验证**：验证每个收到份额的 Dilithium 签名
4. **秘密重构**：收集 ≥ t 个有效份额，通过拉格朗日插值重构原始文件
5. **完整性校验**：重构后验证文件哈希值

**容错能力**：
- 最多可容忍 n - t 个节点失效
- 支持网络节点动态加入/退出
- 份额来源不可预测，提升安全性

### 功能四：本地金库加密

#### 4.1 密码派生与加密机制

本地敏感数据采用金库式加密保护：

- **密钥派生**：PBKDF2HMAC-SHA256，迭代次数 100000+
- **盐值管理**：随机生成 16 字节盐值，存储于 [data/keys/.vault_salt](data/keys/.vault_salt)
- **验证机制**：派生验证哈希，存储于 [data/keys/.vault_verifier](data/keys/.vault_verifier)
- **加密模式**：AES-256-GCM 认证加密，提供完整性保证

#### 4.2 安全特性

- **防暴力破解**：高迭代次数的密钥派生，显著增加破解难度
- **防篡改**：GCM 模式提供认证标签，数据被篡改可立即检测
- **零知识验证**：密码验证过程不暴露任何密码相关信息
- **数据隔离**：敏感数据与普通数据存储隔离

### 功能五：P2P 网络与 NAT 穿透

#### 5.1 UDP 打洞技术

实现完整的 NAT 穿透方案：

- **STUN 协议**：会话遍历 UDP NAT，获取公网映射地址
- **打洞流程**：双向同时发送探测包，建立 UDP 会话
- **NAT 类型**：支持 Full Cone、Restricted Cone、Port Restricted Cone、Symmetric NAT
- **心跳保活**：维持 NAT 端口映射，防止会话超时

#### 5.2 网络架构

- **去中心化**：无中心服务器的P2P 网络架构
- **动态发现**：支持节点动态加入与离开
- **连接复用**：单端口多连接，支持多路复用
- **状态监控**：实时连接状态监控与自动重连

---

## 系统具体使用流程



![framework](./image/framework_flow.png)



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
- 身份文件存储在 `data/keys/node_identity.dat`（AES-256-GCM 加密）
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
