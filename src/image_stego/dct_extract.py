# -*- coding: utf-8 -*-
import cv2
import numpy as np
import struct
from src.config import Config
from src.image_stego.utils import ZigZagUtils, BitStreamUtils

class DCTExtractor:
    """
    基于陈维启论文的 DCT 提取器 (完全复现版)
    核心特性：
    1. 4x4 分块 DCT [论文 2.3节]
    2. 基于中频系数符号的盲提取 [论文 公式(3)]
    """
    def __init__(self):
        self.block_size = Config.DCT_BLOCK_SIZE  # 4
        self.scanner = ZigZagUtils(self.block_size)
        self.target_idx = getattr(Config, 'TARGET_COEFF_INDEX', 11)
        self.target_uv = self.scanner.get_coordinates(self.target_idx)

    def extract(self, stego_path):
        """
        从隐写图像中提取数据
        :param stego_path: 含密图像路径
        :return: 原始数据的 bytes 对象
        """
        # 1. 读取图像
        img = cv2.imread(stego_path)
        if img is None:
            raise ValueError(f"无法读取图像: {stego_path}")
            
        h, w, c = img.shape
        img_float = np.float32(img)
        
        extracted_bits = []
        u, v = self.target_uv
        
        print(f"[DCT] Extracting from {stego_path} (Block {self.block_size}x{self.block_size})...")
        
        # 2. 提取循环 (顺序必须与 Embedder 一致: Channel -> Row -> Col)
        for channel in range(c):
            # 步长为 block_size
            for i in range(0, h, self.block_size):
                for j in range(0, w, self.block_size):
                    # 忽略填充区可能的越界
                    if i + self.block_size > h or j + self.block_size > w:
                        continue

                    # 取出块 -> DCT
                    block = img_float[i : i+self.block_size, j : j+self.block_size, channel]
                    dct_block = cv2.dct(block)
                    coeff = dct_block[u, v]
                    
                    # [论文核心算法 - 公式 (3)]
                    # K12 >= 0 -> W = 1
                    # K12 < 0  -> W = 0
                    if coeff >= 0:
                        extracted_bits.append(1)
                    else:
                        extracted_bits.append(0)

        # 3. 重组比特流
        all_bytes = BitStreamUtils.bits_to_bytes(extracted_bits)
        
        # 4. 解析长度头 (Length Header, 4 bytes)
        if len(all_bytes) < 4:
            raise ValueError("提取的数据太短，无法解析长度头")
            
        data_len = struct.unpack('>I', all_bytes[:4])[0]
        
        # 完整性检查
        if len(all_bytes) < 4 + data_len:
            print(f"Warning: Extracted data incomplete. Expected {data_len}, got {len(all_bytes)-4}")
            # 尝试返回尽可能多的数据
            return all_bytes[4:]
            
        # 5. 截取有效载荷
        payload = all_bytes[4 : 4 + data_len]
        print(f"[DCT] Successfully extracted {len(payload)} bytes.")
        return payload