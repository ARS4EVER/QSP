import collections
from typing import Optional


class HybridCongestionControl:
    """
    混合拥塞控制算法
    
    结合了 TCP Tahoe/Reno 和 TCP Vegas 的优点:
    - 慢启动阶段: cwnd 指数增长
    - 拥塞避免阶段: 基于延迟梯度的 AIMD
    - 丢包检测: 超时和选择性确认(SACK)
    """
    
    def __init__(self, initial_cwnd: float = 10.0, max_cwnd: float = 10000.0, mss: int = 1387):
        self.cwnd = initial_cwnd
        self.ssthresh = 65535.0
        self.min_cwnd = 10.0
        self.max_cwnd = max_cwnd
        self.mss = mss
        
        self.base_rtt: float = float('inf')
        self.smoothed_rtt: float = 0.0
        self.rtt_var: float = 0.0
        self.rto: float = 1.0
        
        self.history_size = 100
        self.delivery_history = collections.deque(maxlen=self.history_size)
        
        self.alpha_max = 10.0
        self.alpha_base = 1.0
        self.eta = 1.5

    def on_ack(self, rtt: float) -> None:
        """处理 ACK 事件，更新 RTT 统计和拥塞窗口"""
        self.delivery_history.append(True)
        
        self.base_rtt = min(self.base_rtt, rtt)
        
        if self.smoothed_rtt == 0.0:
            self.smoothed_rtt = rtt
            self.rtt_var = rtt / 2.0
        else:
            rtt_sample_diff = abs(self.smoothed_rtt - rtt)
            self.rtt_var = 0.75 * self.rtt_var + 0.25 * rtt_sample_diff
            self.smoothed_rtt = 0.875 * self.smoothed_rtt + 0.125 * rtt
            
        self.rto = max(0.2, self.smoothed_rtt + 4 * self.rtt_var)
            
        if self.cwnd < self.ssthresh:
            self.cwnd += 1.0
        else:
            delay_gradient = 0.0
            if self.base_rtt > 0:
                delay_gradient = (rtt - self.base_rtt) / self.base_rtt
                
            if delay_gradient < 0.1:
                alpha = self.alpha_max
            elif delay_gradient < 0.3:
                alpha = self.alpha_max * (1.0 - delay_gradient)
            else:
                alpha = self.alpha_base
                
            self.cwnd += alpha / self.cwnd
            
        self.cwnd = min(self.cwnd, self.max_cwnd)

    def on_loss(self) -> None:
        """处理丢包事件，执行拥塞控制机制"""
        self.delivery_history.append(False)
        
        if len(self.delivery_history) > 0:
            loss_count = sum(1 for success in self.delivery_history if not success)
            lambda_rate = loss_count / len(self.delivery_history)
        else:
            lambda_rate = 0.5
            
        beta = 1.0 - (self.eta * lambda_rate)
        beta = max(0.5, min(0.95, beta))
        
        self.ssthresh = max(self.cwnd * beta, self.min_cwnd)
        self.cwnd = self.ssthresh
        self.rto = min(self.rto * 2.0, 60.0)

    def get_cwnd_packets(self) -> int:
        """返回拥塞窗口大小（以数据包数量为单位）"""
        return int(self.cwnd)
    
    def get_cwnd(self) -> int:
        """返回拥塞窗口大小（以字节数为单位）"""
        return int(self.cwnd * self.mss)
    
    def get_rto(self) -> float:
        """返回重传超时时间（秒）"""
        return self.rto


class CongestionControl:
    """
    延迟梯度拥塞控制器（兼容旧版本接口）
    
    基于 TCP Vegas 的延迟检测机制:
    - 通过监控最小 RTT 估算网络基础延迟
    - 延迟梯度反映队列堆积程度
    - 动态调整发送窗口以避免拥塞
    """
    
    MSS = 1400
    INITIAL_CWND_PACKETS = 2
    MIN_CWND_PACKETS = 1
    QUEUE_THRESHOLD = 0.02
    RTT_ALPHA = 0.125
    
    def __init__(self):
        self.cwnd = self.INITIAL_CWND_PACKETS * self.MSS
        self.ssthresh = 65535 * 10
        
        self.rtt_min = float('inf')
        self.rtt_smoothed = 0.0
        self.rtt_var = 0.0
        
        self.rto = 1.0

    def get_cwnd(self) -> int:
        """返回拥塞窗口大小（字节数）"""
        return int(self.cwnd)

    def get_rto(self) -> float:
        """返回重传超时时间（秒）"""
        return max(0.2, self.rtt_smoothed + 4 * self.rtt_var)

    def on_ack(self, rtt_sample: float):
        """处理 ACK，更新 RTT 统计和拥塞窗口"""
        if self.rtt_smoothed == 0.0:
            self.rtt_smoothed = rtt_sample
            self.rtt_var = rtt_sample / 2
            self.rtt_min = rtt_sample
        else:
            self.rtt_var = (1 - 0.25) * self.rtt_var + 0.25 * abs(self.rtt_smoothed - rtt_sample)
            self.rtt_smoothed = (1 - self.RTT_ALPHA) * self.rtt_smoothed + self.RTT_ALPHA * rtt_sample
            
        if rtt_sample < self.rtt_min:
            self.rtt_min = rtt_sample
            
        gradient = self.rtt_smoothed - self.rtt_min
        
        if gradient < self.QUEUE_THRESHOLD:
            increment = self.MSS * (self.MSS / self.cwnd)
            self.cwnd += increment
        else:
            self.cwnd = max(
                self.MIN_CWND_PACKETS * self.MSS,
                self.cwnd * 0.9
            )

    def on_loss(self):
        """处理丢包，执行拥塞避免"""
        self.ssthresh = max(self.cwnd / 2, 2 * self.MSS)
        
        self.cwnd = max(
            self.MIN_CWND_PACKETS * self.MSS,
            self.cwnd * 0.5
        )
        
        self.rto = min(self.rto * 1.5, 5.0)
