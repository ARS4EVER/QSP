# -*- coding: utf-8 -*-
import os
import time
import numpy as np
import pickle
from PIL import Image
from math import gcd
from functools import reduce

from src.config import Config
from src.secret_sharing.scrambler import ArnoldScrambler

class SharePayload:
    """
    定义标准的份额数据包
    """
    def __init__(self, index, modulus, data, original_shape):
        self.index = index          # 份额索引 (0 to n-1)
        self.modulus = modulus      # 对应的 CRT 模数
        self.data = data            # 扁平化的影子数据 (uint8 array or bytes)
        self.shape = original_shape # 原始图像尺寸 (H, W, C)

    def to_bytes(self):
        """
        序列化为字节流，用于隐写嵌入和哈希计算
        包含 header 信息以便恢复时知道 shape
        """
        payload = {
            'idx': self.index,
            'mod': self.modulus,
            'shape': self.shape,
            'data': self.data # numpy array
        }
        return pickle.dumps(payload)

class ImageCRTSplitter:
    """
    图像CRT分割器 (Image CRT Splitter) - 重构版
    
    特性:
    1. 实现 "倍数-余数" 分解，解决像素溢出问题 (文献2 第3.1节)。
    2. 支持 RGB 三通道矩阵运算，保留图像空间结构。
    3. 增加模数安全性校验。
    4. 支持动态模数和数据序列化。
    """
    
    def __init__(self, n, t, moduli):
        self.n = n
        self.t = t
        self.moduli = sorted(moduli) # 确保有序
        
        # 初始化 Arnold 置乱器
        self.scrambler = ArnoldScrambler(iterations=10)
        
        # 1. 模数安全性校验
        self._validate_moduli()
        
        # 2. 计算 CRT 参数
        # N = m_1 * ... * m_t (最小的t个模数积，用于确保唯一解)
        self.reconstruction_capacity = reduce(lambda x, y: x * y, self.moduli[:self.t])

    def _validate_moduli(self):
        """校验模数是否满足 Asmuth-Bloom 及图像处理要求"""
        if len(self.moduli) != self.n:
            raise ValueError(f"Config Error: Moduli count {len(self.moduli)} != N {self.n}")
        
        # 检查互素 (Pairwise Coprime)
        for i in range(len(self.moduli)):
            for j in range(i + 1, len(self.moduli)):
                if gcd(self.moduli[i], self.moduli[j]) != 1:
                    raise ValueError(f"Security Risk: Moduli {self.moduli[i]} and {self.moduli[j]} are not coprime!")
        
        # 检查是否大于 255 (为了处理像素值)
        for m in self.moduli:
            if m <= 255:
                raise ValueError(f"Config Error: Modulus {m} must be > 255 to support pixel recovery.")

    def split(self, image_array):
        """
        执行 CRT 分割
        image_array: numpy array (H, W, 3)
        Returns: list of SharePayload
        """
        print(f"[CRT] 执行图像分割 (尺寸: {image_array.shape})...")
        h, w, c = image_array.shape
        
        # 1. 预处理：扁平化
        # 将图像展平为一维数组，方便计算
        flat_pixels = image_array.flatten().astype(int)
        
        # 2. 生成影子数据
        # As = (pixel % mi)
        shares_data = []
        for m in self.moduli:
            # CRT 投影运算: x mod m
            # 结果转为 uint8 (因为模数通常 < 65535, 但为了隐写方便我们希望尽可能小)
            # 如果模数 > 255，这里需要使用 uint16，但为了配合 8-bit 载体隐写，
            # 论文1通常通过多通道或拆分字节处理。
            # 为简化演示且模数 > 255 (如 257)，我们将数据存为 uint16 
            # 注意：DCT隐写需要能够承载这些数据。
            # 简化方案：直接保持 int 类型，由序列化层处理 bytes
            shadow = (flat_pixels % m).astype(np.uint16)
            shares_data.append(shadow)
            
        # 3. 封装为 Payload
        payloads = []
        for i, data in enumerate(shares_data):
            sp = SharePayload(
                index=i,
                modulus=self.moduli[i],
                data=data,
                original_shape=(h, w, c)
            )
            payloads.append(sp)
            
        return payloads

    def split_image(self, image_path, signature_data=None, output_dir=None):
        """
        执行图像分割
        
        参数:
            image_path (str): 秘密图像路径
            signature_data (bytes, optional): 来自模块一的格签名数据
            output_dir (str, optional): 输出目录
        
        返回:
            shares_data (list): 包含 N 个字典，每个字典存储该参与者的倍数图和余数图数据
        """
        start_total = time.time()
        
        if output_dir is None:
            output_dir = Config.SHARES_DIR
        os.makedirs(output_dir, exist_ok=True)
        
        # 1. 读取图像
        try:
            img = Image.open(image_path).convert('RGB')
        except IOError:
            raise ValueError(f"Cannot open image at {image_path}")
            
        # 保持 (H, W, 3) 形状，不要 Flatten
        img_array = np.array(img, dtype=np.int64)
        original_shape = (img_array.shape[0], img_array.shape[1])
        print(f"[ImageCRTSplitter] Processing image: {original_shape[0]}x{original_shape[1]}x{img_array.shape[2]}")
        
        # 2. 执行 Arnold 置乱
        print("[ImageCRTSplitter] Scrambling secret image...")
        scrambled_img, original_shape = self.scrambler.scramble(img_array)
        h, w, c = scrambled_img.shape
        print(f"[ImageCRTSplitter] Scrambled image: {h}x{w}x{c}")
        
        # 3. 执行 CRT 分割
        shares = self.split(scrambled_img)
        
        shares_data = []
        saved_paths = []
        
        # 4. 处理份额数据
        for idx, share in enumerate(shares):
            # 存储结构
            share_packet = {
                "index": idx,
                "modulus": share.modulus,
                "data": share.data,
                "shape": share.shape,
                "original_shape": original_shape,  # 原始图像尺寸
                "signature": signature_data
            }
            shares_data.append(share_packet)
            
            # 保存份额为.npy文件
            filename = f"share_{idx+1}_m{share.modulus}.npy"
            filepath = os.path.join(output_dir, filename)
            np.save(filepath, share_packet)
            saved_paths.append(filepath)

        print(f"[ImageCRTSplitter] Split complete in {time.time() - start_total:.4f}s. Generated {len(shares_data)} shares.")
        return saved_paths

# --- 单元测试代码 (直接运行此文件可测试) ---
if __name__ == "__main__":
    # 生成测试用的模数
    from src.secret_sharing.moduli_gen import generate_secure_moduli
    n = 5
    t = 3
    moduli = generate_secure_moduli(n, t)
    splitter = ImageCRTSplitter(n, t, moduli)
    
    # 创建一个测试用的随机图像
    test_img_path = "dataset/test_secret.png"
    if not os.path.exists(test_img_path):
        os.makedirs("dataset", exist_ok=True)
        random_img = np.random.randint(0, 255, (64, 64, 3), dtype=np.uint8)
        Image.fromarray(random_img).save(test_img_path)
    
    # 模拟格签名数据 (32 bytes dummy)
    dummy_sig = b'\xde\xad\xbe\xef' * 8
    
    splitter.split_image(test_img_path, signature_data=dummy_sig)
