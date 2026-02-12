import os
import json
import hashlib
import uuid
from PIL import Image

# 移除隐写相关引用
# from src.image_stego.dct_extract import DCTExtractor 
from src.crypto_lattice.signer import LatticeSigner
from src.crypto_lattice.encryptor import LatticeEncryptor # 必须引入解密器
from src.secret_sharing.reconstructor import ImageCRTReconstructor
from src.config import Config

# 配置路径
ASSET_DIR = "distributed_assets"
KEY_DIR = "my_identities"
OUTPUT_DIR = "recovered_secrets"

def main():
    print("===========================================")
    print("   🟢 QSP 阶段三: 资产解密与恢复 (PQC Core)")
    print("===========================================")

    # 1. 加载清单
    manifest_path = os.path.join(ASSET_DIR, "asset_manifest.json")
    if not os.path.exists(manifest_path):
        print("❌ 错误: 找不到 asset_manifest.json，请检查 ASSET_DIR 路径。")
        return
        
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
        
    t = manifest['threshold']
    print(f"[System] 恢复门限: {t}")
    
    # 2. 初始化工具
    reconstructor = ImageCRTReconstructor()
    valid_shares_payloads = []
    
    # 3. 遍历清单尝试解密
    print("\n--- 开始处理加密分片 ---")
    
    # 我们直接遍历清单中的记录，而不是扫描文件
    for entry in manifest['registry']:
        if len(valid_shares_payloads) >= t:
            print("✨ 已收集足够份额，准备重构。")
            break
            
        owner = entry['owner_alias']
        file_rel_path = entry['file_path']
        file_path = os.path.join(ASSET_DIR, file_rel_path)
        
        print(f"\n👤 处理用户 [{owner}] 的分片...")
        
        # A. 检查文件是否存在
        if not os.path.exists(file_path):
            print(f"   ⚠️  文件缺失: {file_path}")
            continue
            
        # B. 尝试加载私钥 (模拟用户登录)
        sk_path = os.path.join(KEY_DIR, f"{owner}.sk")
        if not os.path.exists(sk_path):
            print(f"   🚫 无权访问: 找不到私钥 {owner}.sk，跳过。")
            continue
            
        try:
            with open(sk_path, 'r') as f:
                sk = json.load(f)
            
            # C. 读取加密数据
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # D. 抗量子解密 (Decryption)
            print(f"   🔓 正在使用私钥解密...")
            # 注意：此处假设 LatticeEncryptor 有 decrypt_data 方法，且参数匹配
            decrypted_bytes = LatticeEncryptor.decrypt_data(sk, encrypted_data)
            
            if not decrypted_bytes:
                print("   ❌ 解密失败: 密文无效或私钥不匹配。")
                continue
                
            # E. 完整性校验 (Hash Check)
            current_hash = hashlib.sha256(decrypted_bytes).hexdigest()
            if current_hash != entry['share_fingerprint']:
                print(f"   ⚠️  篡改警告: 数据哈希不匹配!")
                continue
                
            # F. 反序列化
            payload = reconstructor.deserialize_share(decrypted_bytes)
            if payload:
                valid_shares_payloads.append(payload)
                print("   ✅ 分片加载成功!")
            else:
                print("   ❌ 数据损坏: 无法解析分片结构。")
                
        except Exception as e:
            print(f"   ❌ 处理异常: {str(e)}")
            # import traceback; traceback.print_exc()

    # 4. 执行重构
    if len(valid_shares_payloads) < t:
        print(f"\n❌ 恢复失败: 有效分片不足 ({len(valid_shares_payloads)}/{t})")
        return
        
    print(f"\n[Reconstruct] 启动 CRT 逆运算...")
    try:
        img_arr = reconstructor.reconstruct(valid_shares_payloads)
        
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
        save_path = os.path.join(OUTPUT_DIR, "RECOVERED_SECRET_PQC.png")
        
        Image.fromarray(img_arr).save(save_path)
        print(f"\n🎉 恭喜! 秘密图像已成功恢复!")
        print(f"📂 结果保存在: {save_path}")
        
    except Exception as e:
        print(f"❌ 重构失败: {e}")

if __name__ == "__main__":
    main()