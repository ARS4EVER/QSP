"""
tests/test_large_file_streaming.py
测试 GF(256) 查表加速与大文件流式切分重组的正确性与性能。
"""
import unittest
import os
import time
import tempfile
import sys
import shutil

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.secret_sharing.splitter import SecretSplitter
from src.secret_sharing.reconstructor import SecretReconstructor


class TestLargeFileStreaming(unittest.TestCase):
    def test_high_speed_streaming_shatter_and_recover(self):
        CHUNK_SIZE = 512
        # 生成 200KB 测试数据
        total_size = 200 * 1024 
        original_data = os.urandom(total_size)
        
        n, t = 5, 3
        chunks = [original_data[i:i+CHUNK_SIZE] for i in range(0, len(original_data), CHUNK_SIZE)]
        
        start_time = time.time()
        
        # 模拟流式写入本地硬盘的份额文件
        share_files = {i: bytearray() for i in range(1, n + 1)}
        
        # 1. 流式切分
        for chunk in chunks:
            shares = SecretSplitter.split_secret(chunk, t, n)
            for share_idx, share_data in shares:
                share_files[share_idx].extend(share_data)
                
        split_time = time.time() - start_time
        print(f"\n[Performance] 切分 200KB 数据为 {n} 份耗时: {split_time:.3f} 秒")
        
        # 2. 模拟流式重构 (只用前 T 份)
        recovered_data = bytearray()
        reconstruct_start = time.time()
        
        # 像水流一样一点点切出 T 个切片塞进重构器
        for chunk_idx in range(len(chunks)):
            start_offset = chunk_idx * CHUNK_SIZE
            # 计算最后一块的实际长度
            actual_chunk_len = len(chunks[chunk_idx]) 
            
            chunk_shares = []
            for share_idx in range(1, t + 1):
                chunk_piece = bytes(share_files[share_idx][start_offset:start_offset+actual_chunk_len])
                chunk_shares.append((share_idx, chunk_piece))
                
            recovered_chunk = SecretReconstructor.reconstruct(chunk_shares)
            recovered_data.extend(recovered_chunk)

        rec_time = time.time() - reconstruct_start
        print(f"[Performance] 重构 200KB 数据耗时: {rec_time:.3f} 秒")

        self.assertEqual(bytes(recovered_data), original_data, "数据完整性遭到破坏！")


if __name__ == "__main__":
    unittest.main()
