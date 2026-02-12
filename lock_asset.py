# 修改 QSP-main/lock_asset.py

import os
import argparse
from src.dealer.locker import AssetLocker

def main():
    parser = argparse.ArgumentParser(description="QSP 资产锁定工具 (PQC Only)")
    
    parser.add_argument("--secret", "-s", required=True, help="原始秘密图像路径")
    # 移除了 --covers 参数
    parser.add_argument("--keys", "-k", default="my_identities", help="接收者公钥目录 (.pk)")
    parser.add_argument("--out", "-o", default="distributed_assets", help="输出目录")
    parser.add_argument("--threshold", "-t", type=int, default=3, help="恢复门限 t")
    parser.add_argument("--shares", "-n", type=int, default=5, help="份额数量 n")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.secret):
        print(f"❌ 错误: 找不到秘密图像 {args.secret}")
        return
        
    try:
        locker = AssetLocker()
        locker.lock_and_distribute(
            secret_img_path=args.secret,
            pk_dir=args.keys,
            # cover_dir=args.covers, # 已移除
            output_dir=args.out,
            n=args.shares,
            t=args.threshold
        )
    except Exception as e:
        print(f"\n❌ 锁定失败: {str(e)}")

if __name__ == "__main__":
    main()