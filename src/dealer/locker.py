import os
import shutil
import json
import hashlib
import numpy as np
from PIL import Image

# 引入项目模块
from src.config import Config
from src.secret_sharing.moduli_gen import generate_secure_moduli
from src.secret_sharing.splitter import ImageCRTSplitter
from src.crypto_lattice.encryptor import LatticeEncryptor

class AssetLocker:
    def __init__(self):
        # 不再初始化 DCTEmbedder
        pass

    def lock_and_distribute(self, secret_img_path, pk_dir, output_dir, n, t):
        """
        执行加密资产锁定与分发 (文件存储版)
        """
        print("\n=== [Dealer] 启动资产锁定程序 (PQC加密文件版) ===")
        
        # 1. 收集公钥
        pk_files = sorted([f for f in os.listdir(pk_dir) if f.endswith('.pk')])
        if len(pk_files) < n:
            raise ValueError(f"参与者不足! (公钥数 {len(pk_files)} < 需要 {n})")
            
        public_keys = []
        for pk_f in pk_files[:n]:
            with open(os.path.join(pk_dir, pk_f), 'r') as f:
                pk_data = json.load(f)
                pk_data['_filename'] = pk_f
                public_keys.append(pk_data)

        # 2. 数学准备 (生成模数 & CRT分片)
        print("[Step 2] 正在进行 CRT 秘密分割...")
        moduli = generate_secure_moduli(n, t)
        img = Image.open(secret_img_path).convert('RGB')
        splitter = ImageCRTSplitter(n, t, moduli)
        shares = splitter.split(np.array(img))

        # 3. 准备输出目录
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)

        # 4. 加密与分发
        print("[Step 3] 正在执行抗量子加密并生成分发包...")
        manifest_registry = []
        
        for i in range(n):
            share = shares[i]
            target_pk = public_keys[i]
            
            # 获取用户别名
            owner_alias = target_pk['_filename'].rsplit('.', 1)[0]
            
            # --- A. 序列化 ---
            raw_share_bytes = share.to_bytes()
            share_hash = hashlib.sha256(raw_share_bytes).hexdigest()
            
            # --- B. 抗量子加密 (PQC) ---
            # 使用 LatticeEncryptor 对分片数据进行加密，只有持有对应 SK 的人能解密
            print(f"   -> Encrypting Share #{i+1} for {owner_alias}...")
            encrypted_bytes = LatticeEncryptor.encrypt_data(target_pk, raw_share_bytes)
            
            # --- C. 文件存储 (替代原本的隐写嵌入) ---
            user_dir = os.path.join(output_dir, owner_alias)
            os.makedirs(user_dir, exist_ok=True)
            
            out_filename = f"secure_share_{i+1}{Config.SHARE_EXT}"
            out_path = os.path.join(user_dir, out_filename)
            
            with open(out_path, "wb") as f:
                f.write(encrypted_bytes)
            
            # --- D. 记录清单 ---
            entry = {
                "share_index": i,
                "modulus": moduli[i],
                "file_path": f"{owner_alias}/{out_filename}", # 相对路径
                "share_fingerprint": share_hash, # 原始数据的哈希 (用于解密后验证)
                "owner_alias": owner_alias,
                "public_key_t": target_pk['t'] 
            }
            manifest_registry.append(entry)

        # 5. 生成清单
        print("[Step 4] 生成资产清单...")
        manifest = {
            "version": "QSP-4.0-NoStego",
            "threshold": t,
            "total_shares": n,
            "public_seed": public_keys[0]['public_seed'],
            "registry": manifest_registry
        }
        
        # 保存清单并分发
        manifest_path = os.path.join(output_dir, "asset_manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=4)
            
        for pk in public_keys:
            owner = pk['_filename'].rsplit('.', 1)[0]
            shutil.copy(manifest_path, os.path.join(output_dir, owner, "asset_manifest.json"))
            
        print(f"\n✅ 锁定完成! 加密分片已保存至: {output_dir}")