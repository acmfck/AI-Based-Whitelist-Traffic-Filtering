#!/usr/bin/env python3
"""
生成包含200条威胁流量的CSV测试文件
保存到指定路径: D:\AI\project data
"""

import pandas as pd
import numpy as np
import random
import os
from datetime import datetime, timedelta

# 设置随机种子以确保可重现性
np.random.seed(42)
random.seed(42)


def generate_threat_traffic_data(num_records=1000):
    """生成包含威胁流量的CSV数据 - 高危险性版本"""

    # 定义攻击类型和相应的参数 - 调整为更危险的分布
    attack_types = {
        "DoS": {
            "weight": 0.35,  # 35% DoS攻击 - 高强度
            "duration_range": (30.0, 120.0),  # 更长的攻击持续时间
            "packets_range": (1000, 5000),  # 更多的攻击包
            "bytes_range": (50000, 300000),  # 更大的攻击流量
            "rate_range": (100.0, 500.0),  # 更高的攻击频率
        },
        "Backdoor": {
            "weight": 0.20,  # 20% 后门攻击 - 持续威胁
            "duration_range": (10.0, 60.0),  # 长时间潜伏
            "packets_range": (50, 500),
            "bytes_range": (2000, 25000),
            "rate_range": (10.0, 100.0),
        },
        "Reconnaissance": {
            "weight": 0.15,  # 15% 侦察攻击 - 大规模扫描
            "duration_range": (0.001, 0.5),
            "packets_range": (1, 20),  # 更多的探测包
            "bytes_range": (40, 1000),
            "rate_range": (500.0, 5000.0),  # 极高的扫描频率
        },
        "Exploits": {
            "weight": 0.20,  # 20% 漏洞利用 - 高成功率
            "duration_range": (1.0, 15.0),  # 更长的利用时间
            "packets_range": (10, 300),
            "bytes_range": (500, 15000),
            "rate_range": (20.0, 200.0),
        },
        "Worms": {
            "weight": 0.10,  # 10% 蠕虫攻击 - 自传播
            "duration_range": (5.0, 30.0),  # 更长的传播时间
            "packets_range": (100, 1000),  # 大量复制包
            "bytes_range": (5000, 50000),
            "rate_range": (50.0, 300.0),
        },
    }

    # 计算每种攻击类型的数量
    attack_counts = {}
    total_assigned = 0
    for attack_type, config in attack_types.items():
        count = int(num_records * config["weight"])
        attack_counts[attack_type] = count
        total_assigned += count

    # 将剩余的记录分配给DoS攻击
    remaining = num_records - total_assigned
    attack_counts["DoS"] += remaining

    print(f"攻击类型分布:")
    for attack_type, count in attack_counts.items():
        print(f"  {attack_type}: {count} 条")

    records = []
    flow_id = 1

    for attack_type, count in attack_counts.items():
        config = attack_types[attack_type]

        for i in range(count):
            # 生成基础网络参数
            duration = round(np.random.uniform(*config["duration_range"]), 3)
            src_packets = np.random.randint(*config["packets_range"])
            dst_packets = int(src_packets * np.random.uniform(0.1, 0.8))
            src_bytes = np.random.randint(*config["bytes_range"])
            dst_bytes = int(src_bytes * np.random.uniform(0.2, 1.2))
            rate = round(np.random.uniform(*config["rate_range"]), 1)

            # 根据攻击类型调整参数
            if attack_type == "DoS":
                # DoS攻击特征：高包率、高字节数、持续时间长
                protocol = "tcp"
                service = "-"
                state = "CON"
                tcp_syn_count = int(src_packets * 0.8)
                tcp_fin_count = max(1, int(src_packets * 0.1))
                tcp_rst_count = int(src_packets * 0.1)
                loss_rate = np.random.uniform(0.05, 0.2)

            elif attack_type == "Backdoor":
                # 后门攻击特征：隐蔽性、特定端口
                protocol = "tcp"
                service = random.choice(["ssh", "telnet", "ftp", "-"])
                state = "CON"
                tcp_syn_count = max(1, int(src_packets * 0.1))
                tcp_fin_count = max(1, int(src_packets * 0.1))
                tcp_rst_count = 0
                loss_rate = np.random.uniform(0.0, 0.05)

            elif attack_type == "Reconnaissance":
                # 侦察攻击特征：短连接、小包、多连接
                protocol = "tcp"
                service = "-"
                state = random.choice(["SYN", "RST", "FIN"])
                tcp_syn_count = min(src_packets, 1)
                tcp_fin_count = 0 if state == "SYN" else 1
                tcp_rst_count = 1 if state == "RST" else 0
                loss_rate = 0.0

            elif attack_type == "Exploits":
                # 漏洞利用：目标明确、特定协议
                protocol = random.choice(["tcp", "udp"])
                service = random.choice(["http", "https", "ftp", "ssh", "-"])
                state = random.choice(["CON", "FIN", "RST"])
                tcp_syn_count = max(1, int(src_packets * 0.2))
                tcp_fin_count = max(1, int(src_packets * 0.2))
                tcp_rst_count = int(src_packets * 0.1)
                loss_rate = np.random.uniform(0.0, 0.1)

            else:  # Worms
                # 蠕虫攻击：自复制、网络传播
                protocol = "tcp"
                service = random.choice(["http", "-"])
                state = "CON"
                tcp_syn_count = int(src_packets * 0.3)
                tcp_fin_count = int(src_packets * 0.2)
                tcp_rst_count = int(src_packets * 0.1)
                loss_rate = np.random.uniform(0.02, 0.15)

            # 计算派生字段
            sload = (
                src_bytes / max(duration, 0.001) if duration > 0 else src_bytes * 1000
            )
            dload = (
                dst_bytes / max(duration, 0.001) if duration > 0 else dst_bytes * 1000
            )
            smean = src_bytes / max(src_packets, 1)
            dmean = dst_bytes / max(dst_packets, 1)

            # 生成网络流量记录
            record = {
                "id": flow_id,
                "dur": duration,
                "proto": protocol,
                "service": service,
                "state": state,
                "spkts": src_packets,
                "dpkts": dst_packets,
                "sbytes": src_bytes,
                "dbytes": dst_bytes,
                "rate": rate,
                "sload": round(sload, 2),
                "dload": round(dload, 2),
                "smean": round(smean, 2),
                "dmean": round(dmean, 2),
                "sinpkt": round(duration / max(src_packets, 1), 4),
                "dinpkt": round(duration / max(dst_packets, 1), 4),
                "sjit": round(np.random.uniform(0.0, 1.0), 3),
                "djit": round(np.random.uniform(0.0, 1.0), 3),
                "udp_packet_rate": rate if protocol == "udp" else 0.0,
                "sttl": random.choice([64, 128, 255]),
                "dttl": random.choice([64, 128, 255]),
                "sloss": int(src_packets * loss_rate),
                "dloss": int(dst_packets * loss_rate * 0.5),
                "swin": random.choice([512, 1024, 2048, 4096, 8192]),
                "dwin": random.choice([512, 1024, 2048, 4096, 8192]),
                "stcpb": 0,
                "dtcpb": 0,
                "tcprtt": round(np.random.uniform(0.01, 0.5), 3),
                "synack": round(np.random.uniform(0.01, 0.2), 3),
                "ackdat": round(np.random.uniform(0.005, 0.1), 3),
                "trans_depth": random.randint(0, 3),
                "response_body_len": (
                    random.randint(0, 2000) if service in ["http", "https"] else 0
                ),
                "ct_srv_src": random.randint(1, 20),
                "ct_state_ttl": random.randint(1, 100),
                "ct_dst_ltm": random.randint(1, 50),
                "ct_src_dport_ltm": random.randint(0, 10),
                "ct_dst_sport_ltm": random.randint(0, 5),
                "ct_dst_src_ltm": random.randint(1, 20),
                "ct_src_ltm": random.randint(1, 50),
                "ct_srv_dst": random.randint(1, 100),
                "is_ftp_login": (
                    1 if service == "ftp" and attack_type == "Backdoor" else 0
                ),
                "ct_ftp_cmd": random.randint(0, 5) if service == "ftp" else 0,
                "ct_flw_http_mthd": (
                    random.randint(0, 3) if service in ["http", "https"] else 0
                ),
                "is_sm_ips_ports": random.randint(0, 1),
                "attack_cat": attack_type,
                "label": "Attack",
                "tcp_syn_count": tcp_syn_count,
                "tcp_fin_count": tcp_fin_count,
                "tcp_rst_count": tcp_rst_count,
            }

            records.append(record)
            flow_id += 1

    return pd.DataFrame(records)


def save_threat_data_to_file(df, output_dir="D:\\AI\\project data1", filename=None):
    """保存威胁数据到指定目录"""
    try:
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        # 生成文件名
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_traffic_data_{timestamp}.csv"

        filepath = os.path.join(output_dir, filename)

        # 保存CSV文件
        df.to_csv(filepath, index=False, encoding="utf-8")

        print(f"✅ 威胁流量数据已保存到: {filepath}")
        print(f"📊 数据统计:")
        print(f"   总记录数: {len(df)}")
        print(f"   文件大小: {os.path.getsize(filepath) / 1024:.1f} KB")

        # 显示攻击类型分布
        attack_distribution = df["attack_cat"].value_counts()
        print(f"   攻击类型分布:")
        for attack_type, count in attack_distribution.items():
            percentage = (count / len(df)) * 100
            print(f"     {attack_type}: {count} 条 ({percentage:.1f}%)")

        return filepath

    except Exception as e:
        print(f"❌ 保存文件失败: {e}")
        return None


def generate_additional_normal_traffic(num_records=50):
    """生成一些正常流量作为对比"""
    records = []

    for i in range(num_records):
        protocol = random.choice(["tcp", "udp"])
        service = random.choice(["http", "https", "dns", "ssh", "ftp"])

        if service == "dns":
            protocol = "udp"
            duration = round(np.random.uniform(0.001, 0.5), 3)
            src_packets = random.randint(1, 5)
            dst_packets = random.randint(1, 5)
            src_bytes = random.randint(50, 500)
            dst_bytes = random.randint(50, 500)

        elif service in ["http", "https"]:
            duration = round(np.random.uniform(0.1, 5.0), 3)
            src_packets = random.randint(5, 50)
            dst_packets = random.randint(3, 40)
            src_bytes = random.randint(500, 5000)
            dst_bytes = random.randint(1000, 8000)

        else:  # ssh, ftp, etc.
            duration = round(np.random.uniform(1.0, 30.0), 3)
            src_packets = random.randint(10, 100)
            dst_packets = random.randint(8, 80)
            src_bytes = random.randint(800, 8000)
            dst_bytes = random.randint(600, 6000)

        rate = round((src_packets + dst_packets) / max(duration, 0.001), 1)
        sload = src_bytes / max(duration, 0.001)
        dload = dst_bytes / max(duration, 0.001)

        record = {
            "id": 10000 + i + 1,
            "dur": duration,
            "proto": protocol,
            "service": service,
            "state": random.choice(["CON", "FIN", "RST"]),
            "spkts": src_packets,
            "dpkts": dst_packets,
            "sbytes": src_bytes,
            "dbytes": dst_bytes,
            "rate": rate,
            "sload": round(sload, 2),
            "dload": round(dload, 2),
            "smean": round(src_bytes / max(src_packets, 1), 2),
            "dmean": round(dst_bytes / max(dst_packets, 1), 2),
            "sinpkt": round(duration / max(src_packets, 1), 4),
            "dinpkt": round(duration / max(dst_packets, 1), 4),
            "sjit": round(np.random.uniform(0.0, 0.1), 3),
            "djit": round(np.random.uniform(0.0, 0.1), 3),
            "udp_packet_rate": rate if protocol == "udp" else 0.0,
            "sttl": 64,
            "dttl": 64,
            "sloss": 0,
            "dloss": 0,
            "swin": random.choice([4096, 8192]),
            "dwin": random.choice([4096, 8192]),
            "stcpb": 0,
            "dtcpb": 0,
            "tcprtt": round(np.random.uniform(0.01, 0.1), 3),
            "synack": round(np.random.uniform(0.01, 0.05), 3),
            "ackdat": round(np.random.uniform(0.005, 0.03), 3),
            "trans_depth": random.randint(1, 2),
            "response_body_len": (
                random.randint(100, 1000) if service in ["http", "https"] else 0
            ),
            "ct_srv_src": random.randint(1, 5),
            "ct_state_ttl": random.randint(1, 10),
            "ct_dst_ltm": random.randint(1, 5),
            "ct_src_dport_ltm": 0,
            "ct_dst_sport_ltm": 0,
            "ct_dst_src_ltm": random.randint(1, 3),
            "ct_src_ltm": random.randint(1, 5),
            "ct_srv_dst": random.randint(1, 10),
            "is_ftp_login": 1 if service == "ftp" else 0,
            "ct_ftp_cmd": random.randint(1, 3) if service == "ftp" else 0,
            "ct_flw_http_mthd": (
                random.randint(1, 2) if service in ["http", "https"] else 0
            ),
            "is_sm_ips_ports": 0,
            "attack_cat": "Normal",
            "label": "Normal",
            "tcp_syn_count": 1,
            "tcp_fin_count": 1,
            "tcp_rst_count": 0,
        }

        records.append(record)

    return pd.DataFrame(records)


if __name__ == "__main__":
    print("=== 生成高危险性威胁流量CSV数据文件 ===")
    print("🔴 安全等级: 不安全 (高威胁)")
    print(f"目标记录数: 800条威胁流量 + 200条正常流量")
    print(f"输出目录: D:\\AI\\project data1")
    print()

    # 生成大量威胁流量数据 (80%)
    threat_df = generate_threat_traffic_data(800)

    # 生成少量正常流量作为对比 (20%)
    normal_df = generate_additional_normal_traffic(200)

    # 合并数据
    combined_df = pd.concat([threat_df, normal_df], ignore_index=True)

    # 随机打乱数据顺序
    combined_df = combined_df.sample(frac=1).reset_index(drop=True)

    # 重新分配ID
    combined_df["id"] = range(1, len(combined_df) + 1)

    print(f"\n=== 生成完成 ===")
    print(
        f"🔴 威胁流量: {len(threat_df)} 条 ({len(threat_df)/len(combined_df)*100:.1f}%)"
    )
    print(
        f"🟢 正常流量: {len(normal_df)} 条 ({len(normal_df)/len(combined_df)*100:.1f}%)"
    )
    print(f"📊 总计: {len(combined_df)} 条")
    print(f"⚠️  威胁占比: {len(threat_df)/len(combined_df)*100:.1f}% - 高危险等级")
    print()

    # 保存到指定目录，文件名包含安全等级标识
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    danger_filename = f"high_risk_traffic_data_{timestamp}.csv"
    filepath = save_threat_data_to_file(combined_df, filename=danger_filename)

    if filepath:
        print(f"\n🎉 高危险性测试文件生成完成！")
        print(f"📁 文件路径: {filepath}")
        print(f"� 安全等级: 不安全")
        print(f"💡 建议使用AI检测系统分析此文件")
