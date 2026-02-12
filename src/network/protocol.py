# src/network/protocol.py

class ProtocolTypes:
    """
    通信协议指令集
    """
    # [关键] 身份通告: 连接建立后立即发送明文公钥
    HELLO = "HELLO"
    
    # [关键] 加密握手: Host -> Participant 发送 KEM 封装包
    HANDSHAKE = "HANDSHAKE" 
    
    # LTSS 门限签名流程 (加密传输)
    REQ_COMMITMENT = "REQ_COMMITMENT"   # Host -> Part: 请求承诺
    RES_COMMITMENT = "RES_COMMITMENT"   # Part -> Host: 响应承诺
    
    BROAD_CHALLENGE = "BROAD_CHALLENGE" # Host -> Part: 广播挑战
    RES_RESPONSE = "RES_RESPONSE"       # Part -> Host: 响应签名
    
    # 资产恢复流程 (加密传输)
    REQ_SHARE = "REQ_SHARE"             # Host -> Part: 请求碎片
    RES_SHARE = "RES_SHARE"             # Part -> Host: 发送解密后的碎片
    
    ERROR = "ERROR"
