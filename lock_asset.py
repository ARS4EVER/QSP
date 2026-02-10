import os
import argparse
from src.dealer.locker import AssetLocker

def main():
    parser = argparse.ArgumentParser(description="QSP 资产锁定工具 (Dealer)")
    
    # 定义命令行参数
    parser.add_argument("--secret", "-s", required=True, help="原始秘密图像路径")
    parser.add_argument("--covers", "-c", required=True, help="载体图像目录")
    parser.add_argument("--keys", "-k", default="my_identities", help="接收者公钥目录 (.pk)")
    parser.add_argument("--out", "-o", default="distributed_assets", help="输出目录")
    parser.add_argument("--threshold", "-t", type=int, default=3, help="恢复门限 t")
    parser.add_argument("--shares", "-n", type=int, default=5, help="份额数量 n")
    
    args = parser.parse_args()
    
    # 路径检查
    if not os.path.exists(args.secret):
        print(f"❌ 错误: 找不到秘密图像 {args.secret}")
        return
    if not os.path.exists(args.covers):
        print(f"❌ 错误: 找不到载体目录 {args.covers}")
        return
        
    # 实例化并运行
    try:
        locker = AssetLocker()
        locker.lock_and_distribute(
            secret_img_path=args.secret,
            pk_dir=args.keys,
            cover_dir=args.covers,
            output_dir=args.out,
            n=args.shares,
            t=args.threshold
        )
    except Exception as e:
        print(f"\n❌ 锁定失败: {str(e)}")
        # import traceback
        # traceback.print_exc()

if __name__ == "__main__":
    main()