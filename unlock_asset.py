import os
import json
import hashlib
import uuid
from PIL import Image

from src.image_stego.dct_extract import DCTExtractor
from src.crypto_lattice.signer import LatticeSigner
from src.secret_sharing.reconstructor import ImageCRTReconstructor

# 配置路径
ASSET_DIR = "distributed_assets"
KEY_DIR = "my_identities"
OUTPUT_DIR = "recovered_secrets"

def main():
    print("===========================================")
    print("   🔴 QSP 阶段三: 资产授权与恢复")
    print("===========================================")

    # 1. 检查环境
    manifest_path = os.path.join(ASSET_DIR, "asset_manifest.json")
    if not os.path.exists(manifest_path):
        print("❌ 错误: 找不到资产清单 (asset_manifest.json)")
        return
        
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
        
    t = manifest['threshold']
    print(f"[System] 恢复门限: {t} (至少需要 {t} 个授权份额)")
    
    # 2. 生成会话 ID (防止重放攻击)
    session_id = str(uuid.uuid4())
    print(f"[Session] 本次会话 ID: {session_id}")
    
    # 3. 扫描并处理份额
    extractor = DCTExtractor()
    signer = LatticeSigner()
    reconstructor = ImageCRTReconstructor()
    
    valid_shares_payloads = []
    
    # 获取目录下所有锁定的图片
    stego_files = [f for f in os.listdir(ASSET_DIR) if f.endswith('.png')]
    
    print("\n--- 开始扫描资产碎片 ---")
    for filename in stego_files:
        if len(valid_shares_payloads) >= t:
            print("✨ 已收集足够份额，停止扫描。")
            break
            
        print(f"\n📄 文件: {filename}")
        
        # A. 查找清单记录
        entry = next((item for item in manifest['registry'] if item['carrier_file'] == filename), None)
        if not entry:
            print("   ⚠️  跳过: 清单中未找到记录")
            continue
            
        # B. 隐写提取
        stego_path = os.path.join(ASSET_DIR, filename)
        # 注意：如果你的 DCTExtractor 还没写好，这里会失败。
        # 调试建议：如果提取失败，可以临时读取 .pkl 文件如果 lock_asset 输出了的话
        # 这里假设 extract 返回 bytes
        try:
            share_bytes = extractor.extract(stego_path)
            # 尝试反序列化
            payload = reconstructor.deserialize_share(share_bytes)
            if payload is None:
                 print("   ❌ 提取失败: 数据格式错误")
                 continue
        except Exception as e:
            print(f"   ❌ 提取异常: {e}")
            continue

        # C. 验证指纹 (Integrity Check)
        # 我们必须验证提取出的 bytes 的哈希是否等于清单里的 hash
        # 注意：这里验证的是 share_bytes (序列化后)
        current_hash = hashlib.sha256(share_bytes).hexdigest()
        
        if current_hash != entry['share_fingerprint']:
            print(f"   ❌ 指纹不匹配! (Expected: {entry['share_fingerprint'][:6]}...)")
            print("      数据可能被篡改或提取错误。")
            continue
        
        print(f"   ✅ 数据完整. 锚定身份: {entry['owner_alias']}")
        
        # D. 身份授权 (Sign)
        # 寻找本地私钥
        owner_pk_file = entry['owner_alias'] # e.g., alice.pk
        owner_name = owner_pk_file.replace('.pk', '')
        sk_path = os.path.join(KEY_DIR, f"{owner_name}.sk")
        pk_path = os.path.join(KEY_DIR, owner_pk_file)
        
        if not os.path.exists(sk_path):
            print(f"   ⚠️  无权访问: 本地未找到私钥 {owner_name}.sk")
            continue
            
        print(f"   🔐 正在请求 [{owner_name}] 授权...")
        with open(sk_path, 'r') as f:
            sk = json.load(f)
        with open(pk_path, 'r') as f:
            pk = json.load(f) # 需要公钥来验证
            
        # 构造待签名消息: Hash(Share) + SessionID
        msg = (current_hash + session_id).encode()
        
        # 签名 & 验证
        signature = signer.sign(sk, msg)
        is_valid = signer.verify(pk, msg, signature)
        
        if is_valid:
            print("   ✅ 授权成功! (格签名验证通过)")
            valid_shares_payloads.append(payload)
        else:
            print("   ❌ 授权拒绝! 签名无效。")

    # 4. 执行重构
    if len(valid_shares_payloads) < t:
        print(f"\n❌ 恢复失败: 授权份额不足 ({len(valid_shares_payloads)}/{t})")
        return
        
    print(f"\n[Reconstruct] 启动 CRT 逆运算...")
    try:
        img_arr = reconstructor.reconstruct(valid_shares_payloads)
        
        # 保存
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
        save_path = os.path.join(OUTPUT_DIR, "RECOVERED_SECRET.png")
        
        Image.fromarray(img_arr).save(save_path)
        print(f"\n🎉 恭喜! 秘密图像已成功恢复!")
        print(f"📂 查看结果: {save_path}")
        
    except Exception as e:
        print(f"❌ 重构过程出错: {e}")

if __name__ == "__main__":
    main()