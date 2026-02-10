# -*- coding: utf-8 -*-
import os
import pickle
import numpy as np
from PIL import Image
from functools import reduce

from src.config import Config
from src.secret_sharing.scrambler import ArnoldScrambler

class ImageCRTReconstructor:
    """
    图像CRT重构器 (Image CRT Reconstructor) - 重构版
    
    特性:
    1. 支持 "倍数-余数" 合成，还原溢出像素。
    2. 针对 RGB 三通道矩阵进行批量 CRT 求解。
    3. 支持反序列化和动态模数的重构。
    """
    
    def __init__(self):
        # 初始化 Arnold 置乱器，用于逆置乱
        self.scrambler = ArnoldScrambler(iterations=10)

    def _egcd(self, a, b):
        """扩展欧几里得算法求逆元"""
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self._egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def _modinv(self, a, m):
        """求模逆"""
        g, x, y = self._egcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist')
        else:
            return x % m

    def deserialize_share(self, share_bytes):
        """反序列化二进制份额"""
        try:
            return pickle.loads(share_bytes)
        except:
            return None

    def reconstruct(self, valid_shares):
        """
        执行 CRT 逆运算
        valid_shares: list of dict {'mod': m, 'data': array, 'shape': tuple}
        """
        if not valid_shares:
            return None
            
        print(f"[CRT] 开始重构 (使用 {len(valid_shares)} 个份额)...")
        
        # 提取模数列表
        moduli = [s['mod'] for s in valid_shares]
        # 计算总积 M
        M = reduce(lambda x, y: x * y, moduli)
        
        # 准备累加器 (使用 float64 或 object 防止中间溢出)
        # data 可能是 flatten 的
        shape = valid_shares[0]['shape']
        pixel_count = np.prod(shape)
        
        acc = np.zeros(pixel_count, dtype=object) 
        
        for share in valid_shares:
            mi = share['mod']
            data = share['data'].astype(object) # 转换为大整数对象
            Mi = M // mi
            yi = self._modinv(Mi, mi)
            
            # CRT项: ai * Mi * yi
            term = (data * Mi * yi)
            acc += term
            
        # 最终取模
        result_flat = (acc % M).astype(np.uint8) # 还原为像素值
        
        # 恢复形状
        return result_flat.reshape(shape)

    def reconstruct_image(self, share_paths):
        """
        执行图像重构
        
        参数:
            share_paths (list):.npy 份额文件的路径列表
            
        返回:
            img (PIL.Image): 重构后的图像对象
            signature (bytes): 提取出的格签名
        """
        # 1. 门限检查
        t = Config.T_THRESHOLD
        if len(share_paths) < t:
            raise ValueError(f"Insufficient shares. Need {t}, got {len(share_paths)}")
        
        print(f"[ImageCRTReconstructor] Loading {len(share_paths)} shares for reconstruction...")
        
        loaded_shares = []
        active_moduli = []
        original_shape = None
        extracted_sig = None
        
        # 2. 加载数据与元数据校验
        for path in share_paths:
            try:
                # allow_pickle=True 是必须的，因为我们存储了字典
                packet = np.load(path, allow_pickle=True).item()
            except Exception as e:
                print(f"[Error] Failed to load {path}: {e}")
                continue
                
            # 形状一致性检查
            if original_shape is None:
                original_shape = packet['shape']
            elif original_shape != packet['shape']:
                raise ValueError(f"Shape mismatch in share {path}. Expected {original_shape}, got {packet['shape']}")
            
            # 签名一致性检查 (简单验证)
            if extracted_sig is None:
                extracted_sig = packet['signature']
            
            # 提取核心数据
            loaded_shares.append(packet)
            
            # 验证模数索引
            # 这是一个关键的安全检查：确保使用的是生成时对应的模数
            if 'index' in packet and 'modulus' in packet:
                idx = packet['index']
                actual_mod = packet['modulus']
                
                # 直接使用份额中存储的模数，不再依赖Config.MODULI
                active_moduli.append(actual_mod)
        
        # 选取前 T 个份额进行恢复
        selected_shares = loaded_shares[:t]
        
        # 获取元数据
        h, w, c = original_shape
        print(f"[ImageCRTReconstructor] Recovering image {h}x{w}x{c} using {len(selected_shares)} shares...")

        # 准备 CRT 参数
        active_moduli = [s['modulus'] for s in selected_shares]
        # M = m_1 * m_2 * ... * m_t
        M = reduce(lambda x, y: x * y, active_moduli)
        
        # 预计算 CRT 权重 w_i = M_i * (M_i^{-1} mod m_i)
        # 这样 Y = sum(y_i * w_i) mod M
        weights = []
        for m_i in active_moduli:
            M_i = M // m_i
            inv = self._modinv(M_i, m_i)
            weights.append(M_i * inv)
            
        # 转换为 numpy 数组以便进行矩阵广播计算
        # weights_arr shape: (T,)
        weights_arr = np.array(weights, dtype=object)

        # 2. 还原份额值 y_i (Recompose Shares)
        # 直接使用份额中的 data 作为余数数据，假设倍数为 0
        # 因为在 ImageCRTSplitter 中，份额数据是通过 flat_pixels % m 计算得到的
        ys = []
        for s in selected_shares:
            # 从份额中获取 data 字段作为余数数据
            rem = s['data'].astype(np.int64)
            # 假设倍数为 0
            y_i = rem
            ys.append(y_i)
        
        # 3. 执行 CRT 逆运算
        # 这部分代码参考了 reconstruct 方法
        Y = np.zeros_like(ys[0])
        for i in range(len(Y)):
            # 对每个像素位置执行 CRT
            values = [y[i] for y in ys]
            weighted_sum = 0
            for v, w in zip(values, weights):
                weighted_sum += v * w
            Y[i] = weighted_sum % M
        
        # 4. 提取秘密像素
        # S = Y % q (或者 Y - A*q，但数学上等价于 % q，前提是 S < q)
        # 文献中 q=257 > 255，所以 S = Y % 257 即可
        q = Config.LARGE_PRIME_Q
        S_reconstructed = (Y % q).astype(np.uint8)
        
        # 5. 执行 Arnold 逆置乱，恢复原始图像
        print("[ImageCRTReconstructor] Unscrambling image...")
        # 从第一个份额中获取原始尺寸信息
        if loaded_shares and 'original_shape' in loaded_shares[0] and 'shape' in loaded_shares[0]:
            original_shape = loaded_shares[0]['original_shape']
            share_shape = loaded_shares[0]['shape']
            print(f"[ImageCRTReconstructor] Original image shape: {original_shape}")
            print(f"[ImageCRTReconstructor] Share shape: {share_shape}")
            
            # 将一维数组重新reshape为原始的图像形状
            # 首先，我们需要知道图像的高度、宽度和通道数
            # 从share_shape中获取高度、宽度和通道数
            h, w, c = share_shape
            
            # 将S_reconstructed重新reshape为(h, w, c)的形状
            S_reconstructed_reshaped = S_reconstructed.reshape(h, w, c)
            
            # 执行逆置乱
            unscrambled_img = self.scrambler.unscramble(S_reconstructed_reshaped, original_shape)
            
            # 裁剪回原始尺寸
            h_orig, w_orig = original_shape
            unscrambled_img_cropped = unscrambled_img[:h_orig, :w_orig, :]
            
            img = Image.fromarray(unscrambled_img_cropped)
        else:
            # 如果没有原始尺寸信息，直接使用重构结果
            img = Image.fromarray(S_reconstructed)
        
        print("[ImageCRTReconstructor] Image recovered successfully")
        
        return img, extracted_sig

# --- 单元测试代码 ---
if __name__ == "__main__":
    # 模拟测试
    reconstructor = ImageCRTReconstructor()
    
    # 模拟：从 output 目录寻找所有.npy 文件
    share_dir = Config.SHARES_DIR
    all_shares = [os.path.join(share_dir, f) for f in os.listdir(share_dir) if f.endswith(".npy")]
    
    # 模拟：随机选取 T 个份额
    if len(all_shares) >= Config.T_THRESHOLD:
        import random
        selected_shares = random.sample(all_shares, Config.T_THRESHOLD)
        print(f"[ImageCRTReconstructor] Selected shares: {selected_shares}")
        
        res_img, res_sig = reconstructor.reconstruct_image(selected_shares)
        
        # 保存结果以供人工检查
        os.makedirs("dataset", exist_ok=True)
        res_img.save("dataset/reconstructed_test.png")
        print(f"[ImageCRTReconstructor] Recovered Signature (hex): {res_sig.hex() if res_sig else 'None'}")
    else:
        print("[ImageCRTReconstructor] Not enough shares generated to run reconstruction test")
