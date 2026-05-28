import json
import os


def save_data(data, filepath):
    """将数据保存为 JSON 文件"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f)


def load_data(filepath):
    """从 JSON 文件加载数据"""
    with open(filepath, 'r') as f:
        return json.load(f)