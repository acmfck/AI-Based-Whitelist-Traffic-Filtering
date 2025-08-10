#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成测试数据CSV文件 - 格式与test_with_attacks.csv一致
包含正常流量和各种攻击流量，总共10000条记录
"""

import csv
import random
import numpy as np


# 定义各种攻击类型和正常流量的模板
def generate_normal_traffic():
    """生成正常流量数据"""
    services = ["http", "https", "ssh", "ftp", "dns", "smtp", "telnet", "pop3", "imap"]
    protocols = ["tcp", "udp"]
    states = ["FIN", "CON", "RST"]

    # 随机选择基本参数
    protocol = random.choice(protocols)
    service = random.choice(services) if random.random() > 0.1 else "-"
    state = random.choice(states)

    # 正常流量特征
    dur = round(random.uniform(0.1, 10.0), 3)
    spkts = random.randint(1, 100)
    dpkts = random.randint(1, 100)
    sbytes = random.randint(40, 10000)
    dbytes = random.randint(40, 10000)

    # 计算衍生字段
    rate = round(spkts / dur if dur > 0 else 0, 2)
    sload = round(sbytes / dur if dur > 0 else 0, 2)
    dload = round(dbytes / dur if dur > 0 else 0, 2)
    smean = round(sbytes / spkts if spkts > 0 else 0, 2)
    dmean = round(dbytes / dpkts if dpkts > 0 else 0, 2)

    # 正常的网络参数
    sttl = random.choice([64, 128, 255])
    dttl = random.choice([64, 128, 255])
    swin = random.choice([1024, 2048, 4096, 8192, 16384])
    dwin = random.choice([1024, 2048, 4096, 8192, 16384])

    # TCP标志计数（正常范围）
    tcp_syn = random.randint(0, 3)
    tcp_fin = random.randint(0, 3)
    tcp_rst = random.randint(0, 1)

    return {
        "dur": dur,
        "proto": protocol,
        "service": service,
        "state": state,
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": rate,
        "sload": sload,
        "dload": dload,
        "smean": smean,
        "dmean": dmean,
        "sinpkt": round(random.uniform(0.01, 0.2), 3),
        "dinpkt": round(random.uniform(0.01, 0.2), 3),
        "sjit": round(random.uniform(0.001, 0.1), 3),
        "djit": round(random.uniform(0.001, 0.1), 3),
        "udp_packet_rate": (
            round(random.uniform(0, 10), 1) if protocol == "udp" else 0.0
        ),
        "sttl": sttl,
        "dttl": dttl,
        "sloss": 0,
        "dloss": 0,
        "swin": swin,
        "dwin": dwin,
        "stcpb": 0,
        "dtcpb": 0,
        "tcprtt": round(random.uniform(0.01, 0.2), 3),
        "synack": round(random.uniform(0.005, 0.1), 3),
        "ackdat": round(random.uniform(0.005, 0.05), 3),
        "trans_depth": random.randint(0, 3),
        "response_body_len": random.randint(0, 1000),
        "ct_srv_src": random.randint(1, 10),
        "ct_state_ttl": random.randint(1, 10),
        "ct_dst_ltm": random.randint(1, 10),
        "ct_src_dport_ltm": random.randint(0, 5),
        "ct_dst_sport_ltm": random.randint(0, 5),
        "ct_dst_src_ltm": random.randint(0, 5),
        "ct_src_ltm": random.randint(1, 10),
        "ct_srv_dst": random.randint(1, 10),
        "is_ftp_login": 1 if service == "ftp" and random.random() > 0.7 else 0,
        "ct_ftp_cmd": random.randint(0, 5) if service == "ftp" else 0,
        "ct_flw_http_mthd": random.randint(0, 5) if service in ["http", "https"] else 0,
        "is_sm_ips_ports": random.randint(0, 1),
        "attack_cat": "Normal",
        "label": "Normal",
        "tcp_syn_count": tcp_syn,
        "tcp_fin_count": tcp_fin,
        "tcp_rst_count": tcp_rst,
    }


def generate_dos_attack():
    """生成DoS攻击数据"""
    dur = round(random.uniform(5.0, 30.0), 3)
    spkts = random.randint(500, 5000)  # 大量包
    dpkts = random.randint(10, 200)  # 少量响应
    sbytes = random.randint(25000, 200000)  # 大量字节
    dbytes = random.randint(500, 10000)

    rate = round(spkts / dur, 2)
    sload = round(sbytes / dur, 2)
    dload = round(dbytes / dur, 2)
    smean = round(sbytes / spkts, 2)
    dmean = round(dbytes / dpkts if dpkts > 0 else 0, 2)

    return {
        "dur": dur,
        "proto": "tcp",
        "service": "-",
        "state": "CON",
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": rate,
        "sload": sload,
        "dload": dload,
        "smean": smean,
        "dmean": dmean,
        "sinpkt": round(random.uniform(0.005, 0.05), 3),
        "dinpkt": round(random.uniform(0.1, 0.5), 3),
        "sjit": round(random.uniform(0.3, 1.5), 3),
        "djit": round(random.uniform(0.5, 2.0), 3),
        "udp_packet_rate": 0.0,
        "sttl": 64,
        "dttl": 64,
        "sloss": random.randint(1, 20),
        "dloss": random.randint(0, 5),
        "swin": random.choice([512, 1024]),
        "dwin": 8192,
        "stcpb": 0,
        "dtcpb": 0,
        "tcprtt": round(random.uniform(0.1, 0.5), 3),
        "synack": round(random.uniform(0.05, 0.3), 3),
        "ackdat": round(random.uniform(0.02, 0.15), 3),
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": random.randint(20, 200),
        "ct_state_ttl": random.randint(50, 500),
        "ct_dst_ltm": random.randint(100, 1000),
        "ct_src_dport_ltm": random.randint(10, 100),
        "ct_dst_sport_ltm": random.randint(5, 50),
        "ct_dst_src_ltm": random.randint(10, 100),
        "ct_src_ltm": random.randint(50, 500),
        "ct_srv_dst": random.randint(100, 1000),
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 0,
        "is_sm_ips_ports": 0,
        "attack_cat": "DoS",
        "label": "Attack",
        "tcp_syn_count": random.randint(400, 2000),
        "tcp_fin_count": random.randint(10, 100),
        "tcp_rst_count": random.randint(50, 500),
    }


def generate_reconnaissance_attack():
    """生成侦察攻击数据"""
    return {
        "dur": 0.001,
        "proto": "tcp",
        "service": "-",
        "state": "SYN",
        "spkts": 1,
        "dpkts": 0,
        "sbytes": 40,
        "dbytes": 0,
        "rate": 1000.0,
        "sload": 40000,
        "dload": 0,
        "smean": 40,
        "dmean": 0,
        "sinpkt": 0.001,
        "dinpkt": 0,
        "sjit": 0,
        "djit": 0,
        "udp_packet_rate": 0.0,
        "sttl": 64,
        "dttl": 0,
        "sloss": 0,
        "dloss": 0,
        "swin": 1024,
        "dwin": 0,
        "stcpb": 1,
        "dtcpb": 0,
        "tcprtt": 0,
        "synack": 0,
        "ackdat": 0,
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": 1,
        "ct_state_ttl": 1,
        "ct_dst_ltm": 1,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 0,
        "ct_dst_src_ltm": 0,
        "ct_src_ltm": 1,
        "ct_srv_dst": 1,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 0,
        "is_sm_ips_ports": 0,
        "attack_cat": "Reconnaissance",
        "label": "Attack",
        "tcp_syn_count": 1,
        "tcp_fin_count": 0,
        "tcp_rst_count": 0,
    }


def generate_brute_force_attack():
    """生成暴力破解攻击数据"""
    services = ["ssh", "ftp", "telnet"]
    service = random.choice(services)

    dur = round(random.uniform(3.0, 15.0), 3)
    spkts = random.randint(200, 1000)
    dpkts = random.randint(5, 50)
    sbytes = random.randint(10000, 50000)
    dbytes = random.randint(250, 2500)

    rate = round(spkts / dur, 2)
    sload = round(sbytes / dur, 2)
    dload = round(dbytes / dur, 2)
    smean = round(sbytes / spkts, 2)
    dmean = round(dbytes / dpkts if dpkts > 0 else 0, 2)

    return {
        "dur": dur,
        "proto": "tcp",
        "service": service,
        "state": "CON",
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": rate,
        "sload": sload,
        "dload": dload,
        "smean": smean,
        "dmean": dmean,
        "sinpkt": round(random.uniform(0.008, 0.02), 3),
        "dinpkt": round(random.uniform(0.2, 0.6), 3),
        "sjit": round(random.uniform(0.1, 0.5), 3),
        "djit": round(random.uniform(0.3, 0.8), 3),
        "udp_packet_rate": 0.0,
        "sttl": 64,
        "dttl": 64,
        "sloss": random.randint(1, 10),
        "dloss": random.randint(0, 3),
        "swin": random.choice([1024, 2048]),
        "dwin": 8192,
        "stcpb": 0,
        "dtcpb": 0,
        "tcprtt": round(random.uniform(0.08, 0.25), 3),
        "synack": round(random.uniform(0.04, 0.15), 3),
        "ackdat": round(random.uniform(0.02, 0.08), 3),
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": random.randint(10, 50),
        "ct_state_ttl": random.randint(50, 200),
        "ct_dst_ltm": random.randint(30, 150),
        "ct_src_dport_ltm": random.randint(5, 25),
        "ct_dst_sport_ltm": random.randint(2, 10),
        "ct_dst_src_ltm": random.randint(5, 25),
        "ct_src_ltm": random.randint(20, 100),
        "ct_srv_dst": random.randint(50, 200),
        "is_ftp_login": 1 if service == "ftp" else 0,
        "ct_ftp_cmd": random.randint(5, 20) if service == "ftp" else 0,
        "ct_flw_http_mthd": 0,
        "is_sm_ips_ports": random.randint(0, 1),
        "attack_cat": "Brute Force",
        "label": "Attack",
        "tcp_syn_count": random.randint(150, 800),
        "tcp_fin_count": random.randint(20, 150),
        "tcp_rst_count": random.randint(30, 200),
    }


def generate_backdoor_attack():
    """生成后门攻击数据"""
    return {
        "dur": round(random.uniform(0.1, 2.0), 3),
        "proto": "tcp",
        "service": random.choice(["telnet", "-"]),
        "state": random.choice(["RST", "CON"]),
        "spkts": random.randint(1, 20),
        "dpkts": random.randint(0, 10),
        "sbytes": random.randint(40, 1000),
        "dbytes": random.randint(0, 500),
        "rate": round(random.uniform(5.0, 30.0), 2),
        "sload": round(random.uniform(200, 2000), 2),
        "dload": round(random.uniform(0, 1000), 2),
        "smean": 50,
        "dmean": 50,
        "sinpkt": round(random.uniform(0.05, 0.3), 3),
        "dinpkt": round(random.uniform(0.1, 0.4), 3),
        "sjit": round(random.uniform(0.005, 0.05), 3),
        "djit": round(random.uniform(0.01, 0.08), 3),
        "udp_packet_rate": 0.0,
        "sttl": 64,
        "dttl": 64,
        "sloss": 0,
        "dloss": 0,
        "swin": random.choice([1024, 2048, 4096]),
        "dwin": 8192,
        "stcpb": 0,
        "dtcpb": 0,
        "tcprtt": round(random.uniform(0.02, 0.1), 3),
        "synack": round(random.uniform(0.01, 0.05), 3),
        "ackdat": round(random.uniform(0.005, 0.03), 3),
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": 1,
        "ct_state_ttl": 1,
        "ct_dst_ltm": 1,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 0,
        "ct_dst_src_ltm": 0,
        "ct_src_ltm": 1,
        "ct_srv_dst": 1,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 0,
        "is_sm_ips_ports": 0,
        "attack_cat": "Backdoor",
        "label": "Attack",
        "tcp_syn_count": random.randint(1, 5),
        "tcp_fin_count": random.randint(0, 2),
        "tcp_rst_count": random.randint(0, 3),
    }


def generate_csv_data(total_records=2000):
    """生成CSV数据"""
    data = []

    # 定义各类型数据的比例
    normal_ratio = 0.6  # 60% 正常流量
    dos_ratio = 0.15  # 15% DoS攻击
    recon_ratio = 0.1  # 10% 侦察攻击
    brute_ratio = 0.1  # 10% 暴力破解
    backdoor_ratio = 0.05  # 5% 后门攻击

    # 计算各类型的数量
    normal_count = int(total_records * normal_ratio)
    dos_count = int(total_records * dos_ratio)
    recon_count = int(total_records * recon_ratio)
    brute_count = int(total_records * brute_ratio)
    backdoor_count = (
        total_records - normal_count - dos_count - recon_count - brute_count
    )

    print(f"生成数据分布:")
    print(f"正常流量: {normal_count} 条")
    print(f"DoS攻击: {dos_count} 条")
    print(f"侦察攻击: {recon_count} 条")
    print(f"暴力破解: {brute_count} 条")
    print(f"后门攻击: {backdoor_count} 条")
    print(f"总计: {total_records} 条")

    # 生成各类型数据
    for i in range(normal_count):
        data.append(generate_normal_traffic())

    for i in range(dos_count):
        data.append(generate_dos_attack())

    for i in range(recon_count):
        data.append(generate_reconnaissance_attack())

    for i in range(brute_count):
        data.append(generate_brute_force_attack())

    for i in range(backdoor_count):
        data.append(generate_backdoor_attack())

    # 随机打乱数据
    random.shuffle(data)

    # 添加ID字段
    for i, record in enumerate(data, 1):
        record["id"] = i

    return data


def main():
    """主函数"""
    print("开始生成测试数据文件...")

    # 设置随机种子以确保可重复性
    random.seed(42)
    np.random.seed(42)

    # 生成数据
    data = generate_csv_data(10000)

    # CSV列名（与原文件保持一致）
    fieldnames = [
        "id",
        "dur",
        "proto",
        "service",
        "state",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "rate",
        "sload",
        "dload",
        "smean",
        "dmean",
        "sinpkt",
        "dinpkt",
        "sjit",
        "djit",
        "udp_packet_rate",
        "sttl",
        "dttl",
        "sloss",
        "dloss",
        "swin",
        "dwin",
        "stcpb",
        "dtcpb",
        "tcprtt",
        "synack",
        "ackdat",
        "trans_depth",
        "response_body_len",
        "ct_srv_src",
        "ct_state_ttl",
        "ct_dst_ltm",
        "ct_src_dport_ltm",
        "ct_dst_sport_ltm",
        "ct_dst_src_ltm",
        "ct_src_ltm",
        "ct_srv_dst",
        "is_ftp_login",
        "ct_ftp_cmd",
        "ct_flw_http_mthd",
        "is_sm_ips_ports",
        "attack_cat",
        "label",
        "tcp_syn_count",
        "tcp_fin_count",
        "tcp_rst_count",
    ]

    # 写入CSV文件
    output_file = "testdata2.csv"
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    print(f"✅ 测试数据已生成: {output_file}")
    print(f"📊 包含 {len(data)} 条记录")

    # 统计各类型数量
    attack_stats = {}
    normal_count = 0
    for record in data:
        if record["label"] == "Normal":
            normal_count += 1
        else:
            attack_cat = record["attack_cat"]
            attack_stats[attack_cat] = attack_stats.get(attack_cat, 0) + 1

    print(f"\n📈 数据统计:")
    print(f"正常流量: {normal_count} 条 ({normal_count/len(data)*100:.1f}%)")
    for attack_type, count in attack_stats.items():
        print(f"{attack_type}攻击: {count} 条 ({count/len(data)*100:.1f}%)")


if __name__ == "__main__":
    main()
