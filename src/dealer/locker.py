import os
import shutil
import json
import hashlib
import math
import numpy as np
from PIL import Image
import cv2 

# 引入项目模块
from src.config import Config
from src.secret_sharing.moduli_gen import generate_secure_moduli
from src.secret_sharing.splitter import ImageCRTSplitter
from src.image_stego.dct_embed import DCTEmbedder
from src.image_stego.dct_extract import DCTExtractor 
from src.crypto_lattice.encryptor import LatticeEncryptor 

class AssetLocker:
    def __init__(self):
        self.embedder = DCTEmbedder()
        self.verifier = DCTExtractor() 

    def _calculate_safe_resolution(self, secret_img, cover_path):
        """
        [智能计算] 秘密图像最大安全分辨率
        根据载体大小和隐写密度，计算秘密图像允许的最大尺寸。
        """
        # 1. 读取载体尺寸
        cover = cv2.imread(cover_path)
        if cover is None:
            print(f"[警告] 无法读取载体 {cover_path}，跳过容量检查。")
            return None, None
            
        h_c, w_c, _ = cover.shape

        # 2. 获取隐写参数 (自动适配 Config 中的高密度配置)
        block_size = self.embedder.block_size
        
        # 自动检测使用了多少个系数 (1个 or 14个?)
        if hasattr(self.embedder, 'target_indices'):
            coeffs_count = len(self.embedder.target_indices)
        else:
            coeffs_count = 1 

        # 3. 计算理论最大容量 (bits)
        # 容量 = 块数 * 3通道 * 每块系数数
        total_blocks = (h_c // block_size) * (w_c // block_size)
        capacity_bits = total_blocks * 3 * coeffs_count
        capacity_bytes = capacity_bits / 8

        # 4. 设定安全系数 (保留 30% 余量防止溢出)
        SAFETY_FACTOR = 0.7 
        safe_payload_bytes = capacity_bytes * SAFETY_FACTOR

        # 5. 计算秘密图像单像素开销
        # RGB(3通道) * 2 bytes(uint16) = 6 bytes/pixel
        bytes_per_pixel = 6

        # 6. 计算最大允许像素总数
        max_total_pixels = safe_payload_bytes / bytes_per_pixel

        # 7. 检查当前尺寸
        w_s, h_s = secret_img.size
        current_pixels = w_s * h_s
        
        # 如果当前秘密图像已经比最大允许值小，直接返回不用缩
        if current_pixels <= max_total_pixels:
            return None, None 

        # 8. 计算缩放比例 (保持长宽比)
        scale = math.sqrt(max_total_pixels / current_pixels)
        new_w = int(w_s * scale)
        new_h = int(h_s * scale)

        print(f"\n[智能容量分析]")
        print(f"   - 载体尺寸: {w_c}x{h_c}")
        print(f"   - 隐写密度: {coeffs_count} 系数/块")
        print(f"   - 可用容量: {int(safe_payload_bytes/1024)} KB")
        print(f"   - 原始秘密: {w_s}x{h_s} ({current_pixels} px)")
        print(f"   - 压缩目标: {new_w}x{new_h} ({int(max_total_pixels)} px)")
        print(f"   - 压缩动作: 正在缩小秘密图像...")
        
        return new_w, new_h

    def lock_and_distribute(self, secret_img_path, pk_dir, cover_dir, output_dir, n, t):
        """
        执行加密资产锁定与严格分发
        """
        print("\n=== [Dealer] 启动资产锁定程序 (自适应缩小秘密图像版) ===")
        
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

        # 2. 准备载体列表
        cover_files = sorted([os.path.join(cover_dir, f) for f in os.listdir(cover_dir) 
                             if f.lower().endswith(('.png', '.jpg'))])
        if not cover_files:
            raise ValueError(f"载体目录 {cover_dir} 为空！")

        # 3. 数学准备与图像处理
        moduli = generate_secure_moduli(n, t)
        img = Image.open(secret_img_path).convert('RGB')
        
        # === [核心逻辑] 自适应缩小秘密图像 ===
        # 使用第一张载体图作为基准进行计算
        target_w, target_h = self._calculate_safe_resolution(img, cover_files[0])
        
        if target_w and target_h:
            print(f"[Dealer] ⚠️  载体容量不足，正在将秘密图像缩小至 {target_w}x{target_h}...")
            # 使用 LANCZOS 滤镜进行高质量缩小
            img = img.resize((target_w, target_h), Image.LANCZOS)
        else:
            print(f"[Dealer] ✅ 载体容量充足，秘密图像保持原始分辨率 ({img.size[0]}x{img.size[1]})。")
        # ==================================

        splitter = ImageCRTSplitter(n, t, moduli)
        shares = splitter.split(np.array(img))

        # 4. 准备输出目录
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)

        # 5. 加密锚定与分发
        print("[Step 4] 加密、嵌入并构建分发目录...")
        manifest_registry = []
        
        for i in range(n):
            share = shares[i]
            target_pk = public_keys[i]
            cover_path = cover_files[i % len(cover_files)]
            
            owner_alias = target_pk['_filename'].rsplit('.', 1)[0]
            
            # --- A. 获取原始数据与指纹 ---
            raw_share_bytes = share.to_bytes()
            share_hash = hashlib.sha256(raw_share_bytes).hexdigest()
            
            # --- B. 抗量子加密 ---
            print(f"   -> 处理第 {i+1} 份 (To: {owner_alias})...")
            encrypted_bytes = LatticeEncryptor.encrypt_data(target_pk, raw_share_bytes)
            
            # --- C. 隐写嵌入 ---
            try:
                # 注意：这里我们不对载体做任何 resize，直接嵌入
                stego_img = self.embedder.embed(cover_path, encrypted_bytes)
            except ValueError as e:
                print(f"      ❌ 嵌入失败: 尽管进行了预压缩，数据量仍超出载体容量。")
                print(f"      可能原因: 载体图像太小或纹理过于平滑。")
                raise e

            # --- D. 严格分发 ---
            user_dir = os.path.join(output_dir, owner_alias)
            os.makedirs(user_dir, exist_ok=True)
            
            out_filename = f"locked_asset_{i+1}.png"
            out_path = os.path.join(user_dir, out_filename)
            stego_img.save(out_path)
            
            # --- E. 自检验证 ---
            print(f"      [自检] 验证数据完整性...")
            try:
                extracted_bytes = self.verifier.extract(out_path)
                if len(extracted_bytes) < 100:
                    print(f"      ❌ 严重错误: 数据提取失败!")
                    raise RuntimeError("Self-verification failed")
                else:
                    print(f"      ✅ 校验通过")
            except Exception as e:
                if os.path.exists(out_path):
                    os.remove(out_path)
                raise e
            
            # --- F. 记录清单 ---
            entry = {
                "share_index": i,
                "modulus": moduli[i],
                "carrier_file": f"{owner_alias}/{out_filename}", 
                "share_fingerprint": share_hash,
                "owner_alias": owner_alias
            }
            manifest_registry.append(entry)

        # 6. 生成与分发资产清单
        print("[Step 5] 生成并分发资产清单...")
        manifest = {
            "version": "QSP-3.0-Secure",
            "threshold": t,
            "total_shares": n,
            "public_seed": public_keys[0]['public_seed'],
            "registry": manifest_registry
        }
        
        manifest_path = os.path.join(output_dir, "asset_manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=4)
            
        for pk in public_keys:
            owner = pk['_filename'].rsplit('.', 1)[0]
            shutil.copy(manifest_path, os.path.join(output_dir, owner, "asset_manifest.json"))
            
        print("\n✅ 资产锁定完成!")
        print(f"📂 分发目录结构 ({output_dir}):")
        for pk in public_keys:
            owner = pk['_filename'].rsplit('.', 1)[0]
            print(f"   ├── {owner}/")
