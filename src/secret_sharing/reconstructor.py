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
        
    def reconstruct_from_memory(self, shares_list):
        """
        [新增] 纯内存重构接口
        直接从字典列表中重构图像，不涉及文件 IO。
        
        参数:
            shares_list (list): 包含份额数据的字典列表。
                                每个字典应包含: {'modulus': int, 'data': np.array, 'shape': tuple, 'original_shape': tuple}
        """
        t = Config.T_THRESHOLD if hasattr(Config, 'T_THRESHOLD') else 3
        if len(shares_list) < t:
            raise ValueError(f"Insufficient shares. Need {t}, got {len(shares_list)}")
        
        # 选取前 t 个份额
        selected_shares = shares_list[:t]
        
        # 1. 准备元数据
        original_shape = selected_shares[0].get('original_shape')
        share_shape = selected_shares[0].get('shape')
        
        if not original_shape or not share_shape:
             raise ValueError("Shares missing shape metadata.")
              
        # 2. 准备 CRT 参数
        active_moduli = [s['modulus'] for s in selected_shares]
        M = reduce(lambda x, y: x * y, active_moduli)
        
        weights = []
        for m_i in active_moduli:
            M_i = M // m_i
            inv = self._modinv(M_i, m_i)
            weights.append(M_i * inv)
        weights_arr = np.array(weights, dtype=object)

        # 3. 准备数据矩阵 & 安全检查
        ys = []
        for i, s in enumerate(selected_shares):
            data = s['data'].astype(np.int64)
            mod = s['modulus']
            
            # [安全加固] 检查数据值域，防止恶意构造的大数导致溢出或 DoS
            if np.any(data >= mod):
                 raise ValueError(f"Security Alert: Share {i} contains values larger than modulus {mod}. Possible tampering.")
                 
            if data.shape != (np.prod(share_shape),) and len(data.shape) > 1:
                data = data.flatten()
            ys.append(data)
            
        # 4. 执行 CRT 逆运算 (向量化加速版)
        Y_matrix = np.vstack(ys) 
        weighted_sum = np.sum(Y_matrix * weights_arr[:, np.newaxis], axis=0)
        Y = weighted_sum % M
        
        # 5. 提取秘密像素
        q = Config.LARGE_PRIME_Q if hasattr(Config, 'LARGE_PRIME_Q') else 251
        S_reconstructed = (Y % q).astype(np.uint8)
        
        # 6. 执行 Arnold 逆置乱
        h, w, c = share_shape
        S_reconstructed_reshaped = S_reconstructed.reshape(h, w, c)
        unscrambled_img = self.scrambler.unscramble(S_reconstructed_reshaped, original_shape)
        
        # 裁剪回原始尺寸
        h_orig, w_orig = original_shape
        unscrambled_img_cropped = unscrambled_img[:h_orig, :w_orig, :]
        
        return unscrambled_img_cropped

    def reconstruct_image(self, share_paths):
        """
        执行图像重构
        
        参数:
            share_paths (list):.npy 份额文件的路径列表
            
        返回:
            img (PIL.Image): 重构后的图像对象
            signature (bytes): 提取出的格签名
        """
        print(f"[ImageCRTReconstructor] Loading {len(share_paths)} shares from disk...")
        loaded_shares = []
        extracted_sig = None
        
        for path in share_paths:
            try:
                packet = np.load(path, allow_pickle=True).item()
                loaded_shares.append(packet)
                
                # 提取签名
                if extracted_sig is None and 'signature' in packet:
                    extracted_sig = packet['signature']
                    
            except Exception as e:
                print(f"[Error] Failed to load {path}: {e}")
        
        try:
            img_array = self.reconstruct_from_memory(loaded_shares)
            img = Image.fromarray(img_array)
            print("[ImageCRTReconstructor] Image recovered successfully")
            return img, extracted_sig
        except Exception as e:
            print(f"[Reconstruct Error] {e}")
            raise e

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
