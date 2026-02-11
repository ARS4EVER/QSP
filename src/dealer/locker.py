import os
import shutil
import json
import hashlib
import numpy as np
from PIL import Image
import cv2  # 引入 OpenCV

# 引入项目模块
from src.config import Config
from src.secret_sharing.moduli_gen import generate_secure_moduli
from src.secret_sharing.splitter import ImageCRTSplitter
from src.image_stego.dct_embed import DCTEmbedder
from src.image_stego.dct_extract import DCTExtractor  # 引入提取器用于自检
from src.crypto_lattice.encryptor import LatticeEncryptor  # [新增]

class AssetLocker:
    def __init__(self):
        self.embedder = DCTEmbedder()
        self.verifier = DCTExtractor()  # 初始化验证器，用于自检验证

    def lock_and_distribute(self, secret_img_path, pk_dir, cover_dir, output_dir, n, t):
        """
        执行加密资产锁定与严格分发
        """
        print("\n=== [Dealer] 启动资产锁定程序 (安全分发版) ===")
        
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

        # 2. 数学准备
        moduli = generate_secure_moduli(n, t)
        img = Image.open(secret_img_path).convert('RGB')
        # 设定最大边长限制 
        MAX_DIMENSION = 256 

        w, h = img.size
        if max(w, h) > MAX_DIMENSION:
            scale_ratio = MAX_DIMENSION / max(w, h)
            new_w = int(w * scale_ratio)
            new_h = int(h * scale_ratio)
            
            print(f"\n[Dealer] ⚠️  检测到高分辨率秘密图像 ({w}x{h})")
            print(f"          正在执行智能压缩 -> {new_w}x{new_h} (使用 LANCZOS 算法保持画质)...")
            
            # 使用高质量重采样滤镜进行缩放
            img = img.resize((new_w, new_h), Image.LANCZOS)

        splitter = ImageCRTSplitter(n, t, moduli)
        shares = splitter.split(np.array(img))

        # 3. 准备输出目录 (清空旧数据以防混淆)
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)

        # 4. 加密锚定与分发
        print("[Step 4] 加密、嵌入并构建分发目录...")
        manifest_registry = []
        
        cover_files = sorted([os.path.join(cover_dir, f) for f in os.listdir(cover_dir) 
                             if f.lower().endswith(('.png', '.jpg'))])

        for i in range(n):
            share = shares[i]
            target_pk = public_keys[i]
            cover_path = cover_files[i]
            
            # 获取用户别名 (去掉 .pk 后缀)
            owner_alias = target_pk['_filename'].rsplit('.', 1)[0]
            
            # --- A. 获取原始数据与指纹 ---
            # 这是将来要进入 CRT 重构池的"真身"
            raw_share_bytes = share.to_bytes()
            share_hash = hashlib.sha256(raw_share_bytes).hexdigest()
            
            # --- B. 抗量子加密 (Key Encapsulation) ---
            # 只有 target_pk 对应的 sk 能解开
            print(f"   -> 正在加密第 {i+1} 份 (To: {owner_alias})...")
            encrypted_bytes = LatticeEncryptor.encrypt_data(target_pk, raw_share_bytes)
            
            # --- C. 隐写嵌入 ---
            # 将"密文"藏入图片
            stego_img = self.embedder.embed(cover_path, encrypted_bytes)
            
            # --- D. 严格分发 (创建用户专属文件夹) ---
            # 结构: output_dir/alice/locked_asset_1.png
            user_dir = os.path.join(output_dir, owner_alias)
            os.makedirs(user_dir, exist_ok=True)
            
            out_filename = f"locked_asset_{i+1}.png"
            out_path = os.path.join(user_dir, out_filename)
            stego_img.save(out_path)
            
            # --- E. [关键] 自检验证 (Self-Verification) ---
            print(f"      [自检] 正在验证数据完整性...")
            try:
                # 从刚保存的文件中提取数据
                extracted_bytes = self.verifier.extract(out_path)
                
                # 验证提取的数据长度是否合理
                if len(extracted_bytes) < 100:  # 假设最小数据长度为100字节
                    print(f"      ❌ 严重错误: 第 {i+1} 份数据提取失败!")
                    print(f"         可能原因: 载体图像纹理过于简单(纯色/卡通)或数据量过大。")
                    raise RuntimeError("数据完整性写后校验不通过，终止流程以防止生成无效资产。")
                else:
                    print(f"      ✅ 校验通过 (数据长度合理: {len(extracted_bytes)} bytes)")
                    
            except Exception as e:
                # 删除无效文件
                if os.path.exists(out_path):
                    os.remove(out_path)
                raise e
            
            # --- F. 记录清单 ---
            entry = {
                "share_index": i,
                "modulus": moduli[i],
                # 记录相对路径，GUI 加载时需要拼接
                "carrier_file": f"{owner_alias}/{out_filename}", 
                "share_fingerprint": share_hash, # 指纹必须是"明文"的哈希，用于解密后验证
                "owner_alias": owner_alias  # 使用去掉 .pk 后缀的用户别名，确保一致性
            }
            manifest_registry.append(entry)

        # 5. 生成与分发资产清单
        print("[Step 5] 生成并分发资产清单...")
        manifest = {
            "version": "QSP-3.0-Secure",
            "threshold": t,
            "total_shares": n,
            "public_seed": public_keys[0]['public_seed'],
            "registry": manifest_registry
        }
        
        # 保存总清单
        manifest_path = os.path.join(output_dir, "asset_manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=4)
            
        # [关键] 将清单拷贝给每个用户
        # 这样 Dealer 只需要把 'alice' 文件夹拷给 Alice，里面就什么都有了
        for pk in public_keys:
            owner = pk['_filename'].rsplit('.', 1)[0]
            shutil.copy(manifest_path, os.path.join(output_dir, owner, "asset_manifest.json"))
            
        print("\n✅ 资产锁定完成!")
        print(f"📂 分发目录结构 ({output_dir}):")
        for pk in public_keys:
            owner = pk['_filename'].rsplit('.', 1)[0]
            print(f"   ├── {owner}/ (请将此文件夹拷给 {owner})")
