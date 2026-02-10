# -*- coding: utf-8 -*-
import pickle
import numpy as np
import cv2
from src.image_stego.dct_embed import DCTEmbedder
from src.image_stego.dct_extract import DCTExtractor

class Module3Orchestrator:
    def __init__(self):
        self.embedder = DCTEmbedder()
        self.extractor = DCTExtractor()

    def pack_shadow_data(self, remainder_img, multiple_map):
        """
        将CRT产生的余数图像和倍数映射打包序列化。
        参数:
            remainder_img: 影子图像可视部分 (uint8)
            multiple_map: 溢出倍数部分 (uint8 或 uint16)
        """
        # 使用Pickle或其他高效序列化协议
        data_packet = {
            'r': remainder_img, # Remainder
            'm': multiple_map   # Multiple
        }
        return pickle.dumps(data_packet)

    def unpack_shadow_data(self, data_bytes):
        """
        反序列化还原CRT数据
        """
        return pickle.loads(data_bytes)

    def process_step_3_embedding(self, carrier_img_path, remainder_img, multiple_map):
        """
        执行第三步：嵌入流程
        参数:
            carrier_img_path: 载体图像路径
            remainder_img: 余数图像
            multiple_map: 倍数映射
        返回:
            stego_img: 含密图像
        """
        # 1. 读取载体图像
        carrier_img = cv2.imread(carrier_img_path)
        if carrier_img is None:
            raise ValueError(f"无法读取载体图像: {carrier_img_path}")
        
        # 2. 打包
        payload = self.pack_shadow_data(remainder_img, multiple_map)
        
        # 3. 嵌入
        stego_img = self.embedder.embed(carrier_img, payload)
        
        print(f"[Module 3] 嵌入完成。载荷大小: {len(payload)} bytes")
        return stego_img

    def process_step_3_extraction(self, stego_img_path):
        """
        执行第三步：提取流程
        参数:
            stego_img_path: 含密图像路径
        返回:
            remainder_img: 余数图像
            multiple_map: 倍数映射
        """
        # 1. 读取含密图像
        stego_img = cv2.imread(stego_img_path)
        if stego_img is None:
            raise ValueError(f"无法读取含密图像: {stego_img_path}")
        
        # 2. 提取
        payload = self.extractor.extract(stego_img)
        
        # 3. 解包
        data_packet = self.unpack_shadow_data(payload)
        
        print(f"[Module 3] 提取完成。恢复影子数据。")
        return data_packet['r'], data_packet['m']
