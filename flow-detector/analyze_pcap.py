#!/usr/bin/env python3
"""
分析PCAP文件的工具脚本
"""

import os
import sys
from pathlib import Path

# 添加数据处理模块路径
sys.path.append(os.path.join(os.path.dirname(__file__), "data"))


def analyze_pcap_file(pcap_path):
    """分析PCAP文件并显示统计信息"""

    if not os.path.exists(pcap_path):
        print(f"❌ 文件不存在: {pcap_path}")
        return

    print(f"📊 分析PCAP文件: {pcap_path}")
    print(f"📁 文件大小: {os.path.getsize(pcap_path) / 1024:.2f} KB")

    try:
        # 尝试使用scapy分析原始包数量
        try:
            from scapy.all import rdpcap

            packets = rdpcap(pcap_path)
            print(f"📦 原始数据包数量: {len(packets)}")

            # 分析包的基本信息
            protocols = {}
            for pkt in packets:
                proto = pkt.name if hasattr(pkt, "name") else "Unknown"
                protocols[proto] = protocols.get(proto, 0) + 1

            print("📈 协议分布:")
            for proto, count in sorted(protocols.items()):
                print(f"   {proto}: {count} 包")

        except ImportError:
            print("⚠️ scapy未安装，跳过原始包分析")

        # 使用我们的处理器分析流量
        print("\n🧠 使用AI处理器分析...")
        from data.unsw_nb15_preprocess import AdvancedPcapProcessor

        processor = AdvancedPcapProcessor()
        df = processor.read_pcap_advanced(pcap_path)  # 不限制包数量

        print(f"🌊 提取的网络流数量: {len(df)}")

        if len(df) > 0:
            print("\n📋 流量统计信息:")
            print(f"   平均持续时间: {df['dur'].mean():.3f} 秒")
            print(f"   平均包数: {(df['spkts'] + df['dpkts']).mean():.1f}")
            print(f"   平均字节数: {(df['sbytes'] + df['dbytes']).mean():.0f}")

            # 协议分析
            if "proto" in df.columns:
                proto_counts = df["proto"].value_counts()
                print(f"\n🔗 协议分析:")
                for proto, count in proto_counts.head(5).items():
                    print(f"   协议 {proto}: {count} 流")

            # 服务分析
            if "service" in df.columns:
                service_counts = df["service"].value_counts()
                print(f"\n🌐 服务分析:")
                for service, count in service_counts.head(5).items():
                    print(f"   {service}: {count} 流")

            # 状态分析
            if "state" in df.columns:
                state_counts = df["state"].value_counts()
                print(f"\n🔄 连接状态:")
                for state, count in state_counts.items():
                    print(f"   {state}: {count} 流")

        return df

    except Exception as e:
        print(f"❌ 分析失败: {e}")
        import traceback

        traceback.print_exc()
        return None


if __name__ == "__main__":
    # 分析测试文件
    test_file = "test_anomaly_traffic_500.pcap"

    if len(sys.argv) > 1:
        test_file = sys.argv[1]

    df = analyze_pcap_file(test_file)

    if df is not None and len(df) > 0:
        print(f"\n💾 将分析结果保存为CSV...")
        output_csv = f"analyzed_{Path(test_file).stem}.csv"
        df.to_csv(output_csv, index=False)
        print(f"✅ 已保存: {output_csv}")
        print(f"📊 包含 {len(df)} 行数据，{len(df.columns)} 列特征")
