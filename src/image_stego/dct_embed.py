# -*- coding: utf-8 -*-
import cv2
import numpy as np
import struct
from PIL import Image
from src.config import Config
from src.image_stego.utils import ZigZagUtils, BitStreamUtils, ShareSerializer

class DCTEmbedder:
    """
    基于陈维启论文的 DCT 隐写嵌入器
    - 4x4 分块
    - 符号翻转嵌入算法
    - 自动适配 locker.py 接口
    """
    def __init__(self):
        self.block_size = Config.DCT_BLOCK_SIZE  # 4
        self.scanner = ZigZagUtils(self.block_size)
        self.target_idx = getattr(Config, 'TARGET_COEFF_INDEX', 11)
        self.target_uv = self.scanner.get_coordinates(self.target_idx)
        self.k = getattr(Config, 'EMBEDDING_STRENGTH', 25)

    def _embed_bit_in_block(self, dct_block, bit):
        """
        根据论文公式 (4) 和 (5) 嵌入比特
        """
        u, v = self.target_uv
        coeff = dct_block[u, v]
        k = self.k

        if bit == 0:
            # 目标: 使得系数为负 (coeff < 0)
            if coeff > k:
                coeff = -coeff      # 翻转
            elif -k <= coeff <= k:
                coeff = -k - 1      # 强制设为负
            
            if coeff >= 0: coeff = -k - 1

        else: # bit == 1
            # 目标: 使得系数为正 (coeff >= 0)
            if coeff < -k:
                coeff = -coeff      # 翻转
            elif -k <= coeff <= k:
                coeff = k + 1       # 强制设为正
            
            if coeff < 0: coeff = k + 1

        dct_block[u, v] = coeff
        return dct_block

    def embed(self, carrier_input, data_input):
        """
        嵌入主流程 - 兼容性接口
        :param carrier_input: 图像路径(str) 或 图像矩阵(numpy array)
        :param data_input: 原始字节(bytes) 或 份额字典(dict)
        :return: PIL Image 对象
        """
        # 1. 统一处理输入图像
        if isinstance(carrier_input, str):
            img = cv2.imread(carrier_input)
            if img is None:
                raise ValueError(f"Cannot read image: {carrier_input}")
        else:
            img = carrier_input
            
        h, w, c = img.shape

        # 2. 统一处理数据 [关键修复]
        # locker.py 传入的是 bytes, 不需要再次 serialize
        if isinstance(data_input, bytes):
            payload_bytes = data_input
        else:
            payload_bytes = ShareSerializer.serialize(data_input)

        # 3. 准备数据: [Length (4 bytes)] + [Data]
        length_header = struct.pack('>I', len(payload_bytes))
        full_payload = length_header + payload_bytes
        bits = BitStreamUtils.bytes_to_bits(full_payload)
        total_bits = len(bits)
        
        # 4. 自动填充 (Padding) [关键修复]
        # 确保尺寸是 block_size 的倍数
        pad_h = (self.block_size - h % self.block_size) % self.block_size
        pad_w = (self.block_size - w % self.block_size) % self.block_size
        
        if pad_h > 0 or pad_w > 0:
            print(f"[Embedder] Auto-padding image by {pad_h}x{pad_w}...")
            img = cv2.copyMakeBorder(img, 0, pad_h, 0, pad_w, cv2.BORDER_CONSTANT, value=(0,0,0))
            h, w, c = img.shape

        # 容量检查
        max_capacity = (h // self.block_size) * (w // self.block_size) * c
        if total_bits > max_capacity:
            raise ValueError(f"Payload too large: {total_bits} bits > Capacity {max_capacity} bits")

        # 5. 预处理 (防止 uint8 溢出)
        img = np.clip(img, 1, 254)
        img_float = np.float32(img)

        bit_idx = 0
        print(f"[Embedder] Embedding {len(payload_bytes)} bytes into {h}x{w} image (Block {self.block_size}x{self.block_size})...")

        # 6. 嵌入循环
        for channel in range(c):
            for i in range(0, h, self.block_size):
                for j in range(0, w, self.block_size):
                    if bit_idx >= total_bits:
                        break
                    
                    block = img_float[i:i+self.block_size, j:j+self.block_size, channel]
                    dct_block = cv2.dct(block)
                    dct_block = self._embed_bit_in_block(dct_block, bits[bit_idx])
                    bit_idx += 1
                    block_out = cv2.idct(dct_block)
                    img_float[i:i+self.block_size, j:j+self.block_size, channel] = block_out

            if bit_idx >= total_bits:
                break

        # 7. 转回 uint8 并返回 PIL Image
        stego_img_uint8 = np.clip(img_float, 0, 255).astype(np.uint8)
        return Image.fromarray(cv2.cvtColor(stego_img_uint8, cv2.COLOR_BGR2RGB))
