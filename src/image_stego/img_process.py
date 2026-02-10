# -*- coding: utf-8 -*-
"""
图像处理模块
文件路径: src/image_stego/img_process.py

提供与图像隐写相关的图像处理功能，包括：
1. 图像读取和保存
2. 图像大小调整
3. 图像格式转换
4. 图像预处理和后处理
5. 与DCT嵌入和提取相关的图像处理辅助功能
"""

import cv2
import numpy as np
from src.config import Config
import os

class ImageProcessor:
    """
    图像处理类，提供与图像隐写相关的图像处理功能
    """
    
    def __init__(self):
        """
        初始化图像处理类
        """
        pass
    
    def read_image(self, image_path):
        """
        读取图像
        参数:
            image_path: 图像路径
        返回:
            numpy.ndarray: 图像矩阵 (H, W, 3) BGR格式
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"图像文件不存在: {image_path}")
        
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError(f"无法读取图像: {image_path}")
        
        return img
    
    def save_image(self, image, output_path):
        """
        保存图像
        参数:
            image: 图像矩阵 (H, W, 3) BGR格式
            output_path: 输出路径
        返回:
            bool: 保存是否成功
        """
        # 确保输出目录存在
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        return cv2.imwrite(output_path, image)
    
    def resize_image(self, image, target_size):
        """
        调整图像大小
        参数:
            image: 图像矩阵
            target_size: 目标大小 (width, height)
        返回:
            numpy.ndarray: 调整大小后的图像矩阵
        """
        return cv2.resize(image, target_size, interpolation=cv2.INTER_LINEAR)
    
    def convert_to_gray(self, image):
        """
        将彩色图像转换为灰度图像
        参数:
            image: 彩色图像矩阵 (H, W, 3)
        返回:
            numpy.ndarray: 灰度图像矩阵 (H, W)
        """
        return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    def convert_to_bgr(self, image):
        """
        将灰度图像转换为BGR图像
        参数:
            image: 灰度图像矩阵 (H, W)
        返回:
            numpy.ndarray: BGR图像矩阵 (H, W, 3)
        """
        return cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)
    
    def get_image_info(self, image):
        """
        获取图像信息
        参数:
            image: 图像矩阵
        返回:
            dict: 图像信息，包含高度、宽度、通道数等
        """
        h, w = image.shape[:2]
        channels = image.shape[2] if len(image.shape) > 2 else 1
        
        return {
            'height': h,
            'width': w,
            'channels': channels,
            'size': image.size,
            'dtype': str(image.dtype)
        }
    
    def split_into_blocks(self, image, block_size=8):
        """
        将图像分割为8x8块
        参数:
            image: 图像矩阵
            block_size: 块大小，默认为8
        返回:
            list: 块列表，每个元素为(block_row, block_col, block)
        """
        h, w = image.shape[:2]
        blocks = []
        
        for i in range(0, h, block_size):
            for j in range(0, w, block_size):
                # 确保块大小为8x8
                block_h = min(block_size, h - i)
                block_w = min(block_size, w - j)
                
                if block_h == block_size and block_w == block_size:
                    if len(image.shape) > 2:
                        block = image[i:i+block_size, j:j+block_size, :]
                    else:
                        block = image[i:i+block_size, j:j+block_size]
                    blocks.append((i // block_size, j // block_size, block))
        
        return blocks
    
    def merge_blocks(self, blocks, image_shape, block_size=8):
        """
        将块合并为图像
        参数:
            blocks: 块列表，每个元素为(block_row, block_col, block)
            image_shape: 原始图像形状
            block_size: 块大小，默认为8
        返回:
            numpy.ndarray: 合并后的图像矩阵
        """
        h, w = image_shape[:2]
        channels = image_shape[2] if len(image_shape) > 2 else 1
        
        if channels > 1:
            merged = np.zeros((h, w, channels), dtype=np.uint8)
        else:
            merged = np.zeros((h, w), dtype=np.uint8)
        
        for block_row, block_col, block in blocks:
            start_row = block_row * block_size
            start_col = block_col * block_size
            end_row = start_row + block_size
            end_col = start_col + block_size
            
            if channels > 1:
                merged[start_row:end_row, start_col:end_col, :] = block
            else:
                merged[start_row:end_row, start_col:end_col] = block
        
        return merged
    
    def calculate_psnr(self, original, stego):
        """
        计算峰值信噪比(PSNR)
        参数:
            original: 原始图像
            stego: 含密图像
        返回:
            float: PSNR值 (dB)
        """
        # 确保图像大小相同
        if original.shape != stego.shape:
            raise ValueError("原始图像和含密图像大小不同")
        
        # 计算MSE
        mse = np.mean((original.astype(float) - stego.astype(float)) ** 2)
        if mse == 0:
            return float('inf')
        
        # 计算PSNR
        max_pixel = 255.0
        psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
        
        return psnr
    
    def normalize_image(self, image):
        """
        归一化图像
        参数:
            image: 图像矩阵
        返回:
            numpy.ndarray: 归一化后的图像矩阵
        """
        return image.astype(float) / 255.0
    
    def denormalize_image(self, normalized_image):
        """
        反归一化图像
        参数:
            normalized_image: 归一化后的图像矩阵
        返回:
            numpy.ndarray: 反归一化后的图像矩阵
        """
        return (normalized_image * 255).astype(np.uint8)
    
    def padding_image(self, image, block_size=8):
        """
        对图像进行填充，使其尺寸为块大小的整数倍
        参数:
            image: 图像矩阵
            block_size: 块大小，默认为8
        返回:
            numpy.ndarray: 填充后的图像矩阵
        """
        h, w = image.shape[:2]
        
        # 计算需要填充的大小
        pad_h = (block_size - h % block_size) % block_size
        pad_w = (block_size - w % block_size) % block_size
        
        # 填充图像
        if len(image.shape) > 2:
            padded = np.zeros((h + pad_h, w + pad_w, 3), dtype=np.uint8)
            padded[:h, :w, :] = image
        else:
            padded = np.zeros((h + pad_h, w + pad_w), dtype=np.uint8)
            padded[:h, :w] = image
        
        return padded
    
    def crop_image(self, image, original_shape):
        """
        裁剪图像到原始大小
        参数:
            image: 填充后的图像矩阵
            original_shape: 原始图像形状
        返回:
            numpy.ndarray: 裁剪后的图像矩阵
        """
        h, w = original_shape[:2]
        return image[:h, :w, ...]
