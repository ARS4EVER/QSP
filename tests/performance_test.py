"""
测试模块：性能基准测试 (Performance Benchmark)
路径：tests/test_performance_benchmark.py

测试内容：
1. 不同文件大小下的分割性能 (10KB ~ 100MB)
2. 不同分块数量的影响 (n = 3 ~ 10)
3. 不同恢复门限的影响 (t = 2 ~ n-1)
4. 详细的时间成本统计

测试框架特点：
- 自动生成随机测试文件
- 记录分割和恢复的详细时间数据
- 输出可视化的性能报告
- 支持 CSV 导出用于数据分析
"""

import os
import sys
import time
import json
import csv
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import unittest

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.secret_sharing.splitter import SecretSplitter
from src.secret_sharing.reconstructor import SecretReconstructor


class PerformanceBenchmark:
    """性能基准测试类"""
    
    def __init__(self, output_dir: str = "./benchmark_results"):
        """初始化基准测试"""
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.results = []
        
    def generate_random_file(self, size_bytes: int) -> bytes:
        """
        生成指定大小的随机测试文件
        
        Args:
            size_bytes: 文件大小（字节）
            
        Returns:
            随机文件数据
        """
        return os.urandom(size_bytes)
    
    def measure_split_performance(
        self, 
        data: bytes, 
        t: int, 
        n: int, 
        num_runs: int = 3
    ) -> Dict[str, float]:
        """
        测量文件分割性能
        
        Args:
            data: 待分割的数据
            t: 恢复门限
            n: 总分块数
            num_runs: 运行次数（用于平均）
            
        Returns:
            包含性能指标的字典
            {
                'total_time_ms': 总耗时（毫秒）,
                'avg_time_ms': 平均耗时,
                'throughput_mbps': 吞吐量（MB/s）,
                'time_per_byte_us': 每字节耗时（微秒）
            }
        """
        times = []
        
        for _ in range(num_runs):
            start_time = time.perf_counter()
            shares = SecretSplitter.split_secret(data, t, n)
            end_time = time.perf_counter()
            times.append(end_time - start_time)
        
        avg_time_s = sum(times) / len(times)
        avg_time_ms = avg_time_s * 1000
        
        # 计算吞吐量 (MB/s)
        data_size_mb = len(data) / (1024 * 1024)
        throughput_mbps = data_size_mb / avg_time_s if avg_time_s > 0 else 0
        
        # 计算每字节耗时 (微秒)
        time_per_byte_us = (avg_time_ms * 1000) / len(data) if len(data) > 0 else 0
        
        return {
            'total_time_ms': sum(times) * 1000,
            'avg_time_ms': avg_time_ms,
            'throughput_mbps': throughput_mbps,
            'time_per_byte_us': time_per_byte_us,
            'num_runs': num_runs,
            'min_time_ms': min(times) * 1000,
            'max_time_ms': max(times) * 1000,
        }
    
    def measure_recovery_performance(
        self, 
        shares: List[Tuple[int, bytes]], 
        num_runs: int = 3
    ) -> Dict[str, float]:
        """
        测量文件恢复性能
        
        Args:
            shares: 分享的数据分块
            num_runs: 运行次数（用于平均）
            
        Returns:
            包含性能指标的字典
            {
                'total_time_ms': 总耗时（毫秒）,
                'avg_time_ms': 平均耗时,
                'throughput_mbps': 吞吐量（MB/s）,
                'time_per_byte_us': 每字节耗时（微秒）
            }
        """
        times = []
        
        for _ in range(num_runs):
            start_time = time.perf_counter()
            recovered = SecretReconstructor.reconstruct(shares)
            end_time = time.perf_counter()
            times.append(end_time - start_time)
        
        avg_time_s = sum(times) / len(times)
        avg_time_ms = avg_time_s * 1000
        
        # 计算吞吐量 (MB/s)
        data_size_mb = len(recovered) / (1024 * 1024)
        throughput_mbps = data_size_mb / avg_time_s if avg_time_s > 0 else 0
        
        # 计算每字节耗时 (微秒)
        time_per_byte_us = (avg_time_ms * 1000) / len(recovered) if len(recovered) > 0 else 0
        
        return {
            'total_time_ms': sum(times) * 1000,
            'avg_time_ms': avg_time_ms,
            'throughput_mbps': throughput_mbps,
            'time_per_byte_us': time_per_byte_us,
            'num_runs': num_runs,
            'min_time_ms': min(times) * 1000,
            'max_time_ms': max(times) * 1000,
        }
    
    def benchmark_file_sizes(
        self,
        file_sizes: List[int],
        t: int = 3,
        n: int = 5,
    ) -> List[Dict]:
        """
        测试不同文件大小的性能
        
        Args:
            file_sizes: 文件大小列表（字节）
            t: 恢复门限
            n: 总分块数
            
        Returns:
            性能测试结果列表
        """
        results = []
        
        for size in file_sizes:
            print(f"\n[文件大小测试] 测试 {size / (1024*1024):.1f} MB 文件...")
            
            data = self.generate_random_file(size)
            
            # 测量分割性能
            split_perf = self.measure_split_performance(data, t, n, num_runs=3)
            
            # 执行分割获取分块
            shares = SecretSplitter.split_secret(data, t, n)
            
            # 使用前 t 个分块测试恢复性能
            selected_shares = shares[:t]
            recovery_perf = self.measure_recovery_performance(selected_shares, num_runs=3)
            
            result = {
                'test_type': 'file_size',
                'file_size_bytes': size,
                'file_size_mb': size / (1024 * 1024),
                't': t,
                'n': n,
                'split_avg_time_ms': split_perf['avg_time_ms'],
                'split_throughput_mbps': split_perf['throughput_mbps'],
                'split_time_per_byte_us': split_perf['time_per_byte_us'],
                'recovery_avg_time_ms': recovery_perf['avg_time_ms'],
                'recovery_throughput_mbps': recovery_perf['throughput_mbps'],
                'recovery_time_per_byte_us': recovery_perf['time_per_byte_us'],
            }
            
            results.append(result)
            self.results.append(result)
            
            # 打印详细结果
            self._print_result(result)
        
        return results
    
    def benchmark_threshold_params(
        self,
        file_size: int,
        threshold_params: List[Tuple[int, int]],
    ) -> List[Dict]:
        """
        测试不同阈值参数的性能
        
        Args:
            file_size: 文件大小（字节）
            threshold_params: [(t, n), ...] 阈值参数对列表
            
        Returns:
            性能测试结果列表
        """
        results = []
        data = self.generate_random_file(file_size)
        
        for t, n in threshold_params:
            print(f"\n[阈值参数测试] 测试 t={t}, n={n} (文件大小: {file_size / (1024*1024):.1f} MB)...")
            
            # 测量分割性能
            split_perf = self.measure_split_performance(data, t, n, num_runs=3)
            
            # 执行分割获取分块
            shares = SecretSplitter.split_secret(data, t, n)
            
            # 使用前 t 个分块测试恢复性能
            selected_shares = shares[:t]
            recovery_perf = self.measure_recovery_performance(selected_shares, num_runs=3)
            
            result = {
                'test_type': 'threshold_params',
                'file_size_bytes': file_size,
                'file_size_mb': file_size / (1024 * 1024),
                't': t,
                'n': n,
                'split_avg_time_ms': split_perf['avg_time_ms'],
                'split_throughput_mbps': split_perf['throughput_mbps'],
                'split_time_per_byte_us': split_perf['time_per_byte_us'],
                'recovery_avg_time_ms': recovery_perf['avg_time_ms'],
                'recovery_throughput_mbps': recovery_perf['throughput_mbps'],
                'recovery_time_per_byte_us': recovery_perf['time_per_byte_us'],
            }
            
            results.append(result)
            self.results.append(result)
            
            # 打印详细结果
            self._print_result(result)
        
        return results
    
    def benchmark_recovery_costs(
        self,
        file_size: int,
        t_values: List[int],
        n: int = 5,
    ) -> List[Dict]:
        """
        测试不同恢复门限对恢复成本的影响
        
        Args:
            file_size: 文件大小（字节）
            t_values: 恢复门限值列表
            n: 总分块数
            
        Returns:
            性能测试结果列表
        """
        results = []
        data = self.generate_random_file(file_size)
        
        for t in t_values:
            if t > n:
                print(f"[警告] t={t} > n={n}，跳过此测试")
                continue
            
            print(f"\n[恢复门限测试] 测试 t={t}, n={n} (文件大小: {file_size / (1024*1024):.1f} MB)...")
            
            # 测量分割性能
            split_perf = self.measure_split_performance(data, t, n, num_runs=3)
            
            # 执行分割获取分块
            shares = SecretSplitter.split_secret(data, t, n)
            
            # 测试使用不同数量分块恢复的性能
            recovery_costs = {}
            for use_count in range(t, n + 1):
                selected_shares = shares[:use_count]
                recovery_perf = self.measure_recovery_performance(selected_shares, num_runs=1)
                recovery_costs[use_count] = recovery_perf['avg_time_ms']
            
            result = {
                'test_type': 'recovery_costs',
                'file_size_bytes': file_size,
                'file_size_mb': file_size / (1024 * 1024),
                't': t,
                'n': n,
                'split_avg_time_ms': split_perf['avg_time_ms'],
                'split_throughput_mbps': split_perf['throughput_mbps'],
                'recovery_costs': recovery_costs,
            }
            
            results.append(result)
            self.results.append(result)
            
            # 打印详细结果
            print(f"\n恢复成本详情 (t={t}, n={n}):")
            for use_count, time_ms in recovery_costs.items():
                print(f"  使用 {use_count} 个分块: {time_ms:.3f} ms")
        
        return results
    
    def _print_result(self, result: Dict):
        """打印单个测试结果"""
        print(f"\n{'='*70}")
        print(f"文件大小: {result['file_size_mb']:.2f} MB")
        print(f"分块参数: t={result['t']}, n={result['n']}")
        print(f"{'-'*70}")
        print(f"分割 (Split):")
        print(f"  平均耗时:      {result['split_avg_time_ms']:.3f} ms")
        print(f"  吞吐量:        {result['split_throughput_mbps']:.2f} MB/s")
        print(f"  每字节耗时:    {result['split_time_per_byte_us']:.3f} μs")
        print(f"{'-'*70}")
        print(f"恢复 (Recovery):")
        print(f"  平均耗时:      {result['recovery_avg_time_ms']:.3f} ms")
        print(f"  吞吐量:        {result['recovery_throughput_mbps']:.2f} MB/s")
        print(f"  每字节耗时:    {result['recovery_time_per_byte_us']:.3f} μs")
    
    def export_csv(self, filename: str = "performance_results.csv"):
        """
        导出性能测试结果为 CSV 文件
        
        Args:
            filename: 输出文件名
        """
        filepath = os.path.join(self.output_dir, filename)
        
        if not self.results:
            print("[警告] 没有测试结果可导出")
            return
        
        # 获取所有字段名
        fieldnames = set()
        for result in self.results:
            fieldnames.update(result.keys())
        fieldnames = sorted(list(fieldnames))
        
        # 写入 CSV
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in self.results:
                # 处理嵌套字典（如 recovery_costs）
                row = {}
                for key, value in result.items():
                    if isinstance(value, dict):
                        row[key] = json.dumps(value)
                    else:
                        row[key] = value
                writer.writerow(row)
        
        print(f"\n✓ 结果已导出到: {filepath}")
    
    def export_json(self, filename: str = "performance_results.json"):
        """
        导出性能测试结果为 JSON 文件
        
        Args:
            filename: 输出文件名
        """
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n✓ 结果已导出到: {filepath}")
    
    def generate_html_report(self, filename: str = "performance_report.html"):
        """
        生成 HTML 性能报告
        
        Args:
            filename: 输出文件名
        """
        filepath = os.path.join(self.output_dir, filename)
        
        html_content = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>QSP 性能基准测试报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .metric { font-weight: bold; color: #2196F3; }
        .section { margin: 30px 0; }
    </style>
</head>
<body>
    <h1>QSP 抗量子秘密文件共享系统</h1>
    <h2>性能基准测试报告</h2>
"""
        
        # 按测试类型分类
        test_types = {}
        for result in self.results:
            test_type = result.get('test_type', 'unknown')
            if test_type not in test_types:
                test_types[test_type] = []
            test_types[test_type].append(result)
        
        for test_type, results in test_types.items():
            html_content += f"""
    <div class="section">
        <h3>测试类型: {test_type}</h3>
        <table>
            <tr>
                <th>文件大小 (MB)</th>
                <th>t (恢复门限)</th>
                <th>n (分块数)</th>
                <th>分割时间 (ms)</th>
                <th>分割吞吐量 (MB/s)</th>
                <th>恢复时间 (ms)</th>
                <th>恢复吞吐量 (MB/s)</th>
            </tr>
"""
            for result in results:
                html_content += f"""
            <tr>
                <td>{result.get('file_size_mb', 'N/A'):.2f}</td>
                <td>{result.get('t', 'N/A')}</td>
                <td>{result.get('n', 'N/A')}</td>
                <td class="metric">{result.get('split_avg_time_ms', 0):.3f}</td>
                <td class="metric">{result.get('split_throughput_mbps', 0):.2f}</td>
                <td class="metric">{result.get('recovery_avg_time_ms', 0):.3f}</td>
                <td class="metric">{result.get('recovery_throughput_mbps', 0):.2f}</td>
            </tr>
"""
            html_content += """
        </table>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\n✓ HTML 报告已生成: {filepath}")


class TestPerformanceBenchmark(unittest.TestCase):
    """单元测试类"""
    
    @classmethod
    def setUpClass(cls):
        """初始化测试环境"""
        cls.benchmark = PerformanceBenchmark()
    
    def test_01_small_file_split_and_recovery(self):
        """测试小文件的分割和恢复"""
        print("\n\n" + "="*70)
        print("测试1: 小文件测试 (10KB, 100KB, 1MB)")
        print("="*70)
        
        file_sizes = [10 * 1024, 100 * 1024, 1024 * 1024]  # 10KB, 100KB, 1MB
        self.benchmark.benchmark_file_sizes(file_sizes, t=3, n=5)
    
    def test_02_medium_file_split_and_recovery(self):
        """测试中等文件的分割和恢复"""
        print("\n\n" + "="*70)
        print("测试2: 中等文件测试 (5MB, 10MB, 20MB)")
        print("="*70)
        
        file_sizes = [5 * 1024 * 1024, 10 * 1024 * 1024, 20 * 1024 * 1024]
        self.benchmark.benchmark_file_sizes(file_sizes, t=3, n=5)
    
    def test_03_large_file_split_and_recovery(self):
        """测试大文件的分割和恢复"""
        print("\n\n" + "="*70)
        print("测试3: 大文件测试 (50MB, 100MB)")
        print("="*70)
        
        file_sizes = [50 * 1024 * 1024, 100 * 1024 * 1024]
        self.benchmark.benchmark_file_sizes(file_sizes, t=3, n=5)
    
    def test_04_threshold_variation(self):
        """测试不同阈值参数的影响"""
        print("\n\n" + "="*70)
        print("测试4: 阈值参数变化测试")
        print("="*70)
        
        file_size = 10 * 1024 * 1024  # 10MB
        threshold_params = [
            (2, 3), (2, 4), (2, 5),
            (3, 5), (3, 6), (3, 7),
            (4, 6), (4, 7), (4, 8),
            (5, 7), (5, 8), (5, 10)
        ]
        self.benchmark.benchmark_threshold_params(file_size, threshold_params)
    
    def test_05_recovery_cost_increase(self):
        """测试恢复成本随分块数增加的变化"""
        print("\n\n" + "="*70)
        print("测试5: 恢复成本增长测试")
        print("="*70)
        
        file_size = 10 * 1024 * 1024  # 10MB
        self.benchmark.benchmark_recovery_costs(file_size, t_values=[3, 4, 5], n=8)
    
    @classmethod
    def tearDownClass(cls):
        """生成报告并清理"""
        print("\n\n" + "="*70)
        print("生成测试报告...")
        print("="*70)
        
        cls.benchmark.export_csv("performance_results.csv")
        cls.benchmark.export_json("performance_results.json")
        cls.benchmark.generate_html_report("performance_report.html")
        
        print(f"\n✓ 所有测试已完成")
        print(f"✓ 结果已保存到: {cls.benchmark.output_dir}/")


if __name__ == '__main__':
    # 运行测试
    unittest.main(verbosity=2)
