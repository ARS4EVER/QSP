# -*- coding: utf-8 -*-
import pickle
import zlib
import numpy as np

class ShareSerializer:
    """
    负责将份额字典(Share Dict)序列化为可嵌入的字节流，并提供压缩功能。
    """
    
    @staticmethod
    def serialize(share_dict):
        """
        字典 -> 压缩字节流
        """
        # 1. 使用 pickle 序列化对象
        try:
            raw_bytes = pickle.dumps(share_dict)
        except Exception as e:
            raise ValueError(f"Serialization failed: {e}")
            
        # 2. 使用 zlib 压缩 (Level 9 - 最大压缩)
        compressed_bytes = zlib.compress(raw_bytes, level=9)
        
        print(f"[Serializer] Raw: {len(raw_bytes)} bytes -> Compressed: {len(compressed_bytes)} bytes")
        return compressed_bytes

    @staticmethod
    def deserialize(compressed_bytes):
        """
        压缩字节流 -> 字典
        """
        try:
            # 1. 解压
            raw_bytes = zlib.decompress(compressed_bytes)
            # 2. 反序列化
            share_dict = pickle.loads(raw_bytes)
            return share_dict
        except Exception as e:
            raise ValueError(f"Deserialization failed: {e}")


class ZigZagUtils:
    """
    处理DCT块的Zigzag扫描顺序工具
    """
    def __init__(self, block_size=8):
        self.block_size = block_size
        self.zigzag_map = self._generate_zigzag_map()

    def _generate_zigzag_map(self):
        """
        生成Zigzag扫描坐标映射表。
        返回: list of (row, col) tuples
        """
        # [修正] 论文 4x4 ZigZag 扫描顺序
        if self.block_size == 4:
            return [
                (0, 0), (0, 1), (1, 0), (2, 0), 
                (1, 1), (0, 2), (0, 3), (1, 2), 
                (2, 1), (3, 0), (3, 1), (2, 2), # Index 11 is (2,2)
                (1, 3), (2, 3), (3, 2), (3, 3)
            ]
        # 标准 8x8 (兼容旧代码)
        elif self.block_size == 8:
            return [
                (0, 0), (0, 1), (1, 0), (2, 0), (1, 1), (0, 2), (0, 3), (1, 2),
                (2, 1), (3, 0), (4, 0), (3, 1), (2, 2), (1, 3), (0, 4), (0, 5),
                (1, 4), (2, 3), (3, 2), (4, 1), (5, 0), (6, 0), (5, 1), (4, 2),
                (3, 3), (2, 4), (1, 5), (0, 6), (0, 7), (1, 6), (2, 5), (3, 4),
                (4, 3), (5, 2), (6, 1), (7, 0), (7, 1), (6, 2), (5, 3), (4, 4),
                (3, 5), (2, 6), (1, 7), (2, 7), (3, 6), (4, 5), (5, 4), (6, 3),
                (7, 2), (7, 3), (6, 4), (5, 5), (4, 6), (3, 7), (4, 7), (5, 6),
                (6, 5), (7, 4), (7, 5), (6, 6), (5, 7), (6, 7), (7, 6), (7, 7)
            ]
        else:
            # 对于其他尺寸的块，使用原始算法
            lines = [[] for _ in range(2 * self.block_size - 1)]
            for y in range(self.block_size):
                for x in range(self.block_size):
                    lines[y + x].append((y, x))
            
            zigzag_coords = []
            for i, line in enumerate(lines):
                if i % 2 == 0:
                    zigzag_coords.extend(line[::-1]) # 偶数对角线：右上到左下
                else:
                    zigzag_coords.extend(line)       # 奇数对角线：左下到右上
            return zigzag_coords

    def get_coordinates(self, index):
        """
        获取指定Zigzag索引对应的二维矩阵坐标 (row, col)
        """
        if 0 <= index < len(self.zigzag_map):
            return self.zigzag_map[index]
        raise ValueError(f"索引 {index} 超出块尺寸范围")

class BitStreamUtils:
    """
    处理二进制位流转换的工具
    """
    @staticmethod
    def bytes_to_bits(data_bytes):
        """
        将字节串转换为比特列表 [0, 1, 0,...]
        """
        bits = []
        for byte in data_bytes:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @staticmethod
    def bits_to_bytes(bits):
        """
        将比特列表转换回字节串
        """
        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte_chunk = bits[i:i+8]
            if len(byte_chunk) < 8:
                break # 丢弃末尾不足一个字节的填充位
            val = 0
            for bit in byte_chunk:
                val = (val << 1) | bit
            byte_array.append(val)
        return bytes(byte_array)

    @staticmethod
    def int_to_bytes(number, size=4):
        """将整数转换为固定长度字节"""
        return number.to_bytes(size, byteorder='big')

    @staticmethod
    def bytes_to_int(byte_data):
        """将字节转换为整数"""
        return int.from_bytes(byte_data, byteorder='big')
