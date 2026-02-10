# -*- coding: utf-8 -*-
"""
Arnold 图像置乱器
用于在 CRT 秘密共享前对图像进行置乱，确保生成的份额图像具有伪随机性
"""

import numpy as np

class ArnoldScrambler:
    """
    Arnold 图像置乱器 (Arnold Cat Map)
    用于消除图像像素的空间相关性，确保生成的份额图像不泄露原图纹理。
    """
    def __init__(self, a=1, b=1, iterations=16):
        """
        初始化置乱参数
        :param a: 参数 a
        :param b: 参数 b
        :param iterations: 置乱轮数，通常 10-20 轮即可达到很好的混淆效果
        """
        self.a = a
        self.b = b
        self.iterations = iterations

    def scramble(self, image_array):
        """
        对图像进行 Arnold 置乱
        :param image_array: numpy array, shape (H, W, C)
        :return: 置乱后的 numpy array 和原始尺寸
        """
        h, w, c = image_array.shape
        
        # 自动 Padding 到正方形
        n = max(h, w)
        padded_img = np.zeros((n, n, c), dtype=image_array.dtype)
        padded_img[:h, :w, :] = image_array
        
        # 使用最稳妥的迭代搬运法
        img_curr = padded_img.copy()
        for _ in range(self.iterations):
            img_next = np.zeros_like(img_curr)
            # 生成所有坐标
            yy, xx = np.indices((n, n))
            # 计算新坐标
            xx_new = (xx + self.b * yy) % n
            yy_new = (self.a * xx + (self.a * self.b + 1) * yy) % n
            # 赋值
            img_next[yy_new, xx_new] = img_curr[yy, xx]
            img_curr = img_next
            
        return img_curr, (h, w) # 返回置乱图和原始尺寸

    def unscramble(self, image_array, original_shape=None):
        """
        对图像进行 Arnold 逆置乱
        :param image_array: numpy array, shape (N, N, C)
        :param original_shape: 原始图像尺寸 (H, W)
        :return: 逆置乱后的 numpy array
        """
        n, _, c = image_array.shape
        
        # 使用最稳妥的迭代搬运法
        img_curr = image_array.copy()
        for _ in range(self.iterations):
            img_next = np.zeros_like(img_curr)
            yy, xx = np.indices((n, n))
            
            # 逆变换公式
            xx_old = ((self.a * self.b + 1) * xx - self.b * yy) % n
            yy_old = (-self.a * xx + yy) % n
            
            img_next[yy_old, xx_old] = img_curr[yy, xx]
            img_curr = img_next
            
        # 裁剪回原始尺寸
        if original_shape:
            h, w = original_shape
            return img_curr[:h, :w, :]
        return img_curr