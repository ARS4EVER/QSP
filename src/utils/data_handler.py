import json
import os

def save_data(data, filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f)

def load_data(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)