#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成测试用的PCAP文件，包含正常和异常流量数据
需要安装: pip install scapy
"""

import random
import time
from datetime import datetime, timedelta
import os

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    SCAPY_AVAILABLE = True
except ImportError:
    print("⚠️ 需要安装scapy库: pip install scapy")
    SCAPY_AVAILABLE = False


def generate_normal_packet(
    src_ip, dst_ip, src_port=None, dst_port=None, protocol="TCP"
):
    """生成正常的网络包"""
    if protocol == "TCP":
        src_port = src_port or random.randint(1024, 65535)
        dst_port = dst_port or random.choice([80, 443, 22, 21, 25])
        packet = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags="S")
        )
        # 添加一些正常的payload
        payload_size = random.randint(64, 1500)
        payload = b"A" * payload_size
        packet = packet / Raw(load=payload)
    elif protocol == "UDP":
        src_port = src_port or random.randint(1024, 65535)
        dst_port = dst_port or random.choice([53, 67, 68, 123, 161])
        packet = (
            Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
        )
        # DNS查询类似的payload
        payload = (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
        )
        packet = packet / Raw(load=payload)
    elif protocol == "ICMP":
        packet = (
            Ether() / IP(src=src_ip, dst=dst_ip) / ICMP(type=8, code=0)
        )  # Echo Request
        packet = packet / Raw(load=b"ICMP ping test data")

    return packet


def generate_attack_packet(attack_type, src_ip, dst_ip):
    """生成攻击/异常包"""
    if attack_type == "port_scan":
        # 端口扫描 - 快速扫描多个端口
        dst_port = random.randint(1, 1024)
        packet = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(40000, 50000), dport=dst_port, flags="S")
        )

    elif attack_type == "ddos":
        # DDoS攻击 - 大量小包
        packet = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        )
        # 异常小的payload或无payload
        if random.random() > 0.5:
            packet = packet / Raw(load=b"X" * random.randint(1, 10))

    elif attack_type == "brute_force":
        # 暴力破解 - 针对SSH/FTP等服务
        dst_port = random.choice([22, 21, 23, 3389])
        packet = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(40000, 60000), dport=dst_port, flags="PA")
        )
        # 模拟登录尝试的payload
        fake_login = (
            f"user{random.randint(1,1000)}:pass{random.randint(1,1000)}".encode()
        )
        packet = packet / Raw(load=fake_login)

    elif attack_type == "malware":
        # 恶意软件通信 - 异常端口和协议
        dst_port = random.choice([6666, 1337, 31337, 4444, 8080])
        packet = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="PA")
        )
        # 可疑的二进制payload
        suspicious_payload = bytes(
            [random.randint(0, 255) for _ in range(random.randint(100, 500))]
        )
        packet = packet / Raw(load=suspicious_payload)

    elif attack_type == "reconnaissance":
        # 网络侦察 - ICMP扫描或异常探测
        packet = Ether() / IP(src=src_ip, dst=dst_ip) / ICMP(type=8, code=0)
        # 异常大的ICMP包
        large_payload = b"PING" * random.randint(100, 400)
        packet = packet / Raw(load=large_payload)

    elif attack_type == "backdoor":
        # 后门通信 - 高端口通信
        src_port = random.randint(50000, 65535)
        dst_port = random.randint(50000, 65535)
        packet = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags="PA")
        )
        # 加密或编码的payload
        backdoor_payload = b"\x41\x42\x43\x44" * random.randint(20, 100)
        packet = packet / Raw(load=backdoor_payload)

    return packet


def generate_test_pcap(filename="test_anomaly_traffic.pcap", num_packets=500):
    """生成包含异常数据的测试PCAP文件"""
    if not SCAPY_AVAILABLE:
        print("❌ 无法生成PCAP文件，请安装scapy库")
        return False

    print(f"🚀 开始生成测试PCAP文件: {filename}")
    print(f"📊 总包数: {num_packets}")

    packets = []

    # 定义IP地址池
    normal_ips = [
        "192.168.1.10",
        "192.168.1.20",
        "192.168.1.30",
        "10.0.0.5",
        "172.16.0.10",
    ]
    target_ips = ["192.168.1.100", "10.0.0.1", "172.16.0.1", "8.8.8.8", "1.1.1.1"]
    attacker_ips = ["203.0.113.5", "198.51.100.10", "192.0.2.15", "169.254.1.1"]

    # 攻击类型分布
    attack_types = [
        "port_scan",
        "ddos",
        "brute_force",
        "malware",
        "reconnaissance",
        "backdoor",
    ]

    # 生成数据包
    normal_count = int(num_packets * 0.7)  # 70% 正常流量
    attack_count = num_packets - normal_count  # 30% 异常流量

    print(f"📋 数据分布: {normal_count} 正常包, {attack_count} 异常包")

    # 生成正常流量
    for i in range(normal_count):
        src_ip = random.choice(normal_ips)
        dst_ip = random.choice(target_ips)
        protocol = random.choice(["TCP", "UDP", "ICMP"])

        packet = generate_normal_packet(src_ip, dst_ip, protocol=protocol)
        packets.append(packet)

        if (i + 1) % 100 == 0:
            print(f"✅ 已生成 {i + 1} 个正常包")

    # 生成攻击流量
    for i in range(attack_count):
        attack_type = random.choice(attack_types)
        src_ip = random.choice(attacker_ips)
        dst_ip = random.choice(target_ips)

        packet = generate_attack_packet(attack_type, src_ip, dst_ip)
        packets.append(packet)

        if (i + 1) % 50 == 0:
            print(f"⚠️ 已生成 {i + 1} 个异常包 (类型: {attack_type})")

    # 打乱包的顺序，模拟真实网络环境
    random.shuffle(packets)

    # 为包添加时间戳
    base_time = time.time() - 3600  # 1小时前开始
    for i, packet in enumerate(packets):
        # 随机间隔时间，模拟真实网络流量
        if i < len(packets) * 0.3:  # 前30%的包模拟攻击爆发，间隔较短
            time_offset = i * random.uniform(0.001, 0.01)
        else:
            time_offset = i * random.uniform(0.1, 2.0)

        packet.time = base_time + time_offset

    # 按时间排序
    packets.sort(key=lambda p: p.time)

    # 写入PCAP文件
    try:
        wrpcap(filename, packets)
        print(f"✅ PCAP文件生成成功: {filename}")
        print(f"📁 文件大小: {os.path.getsize(filename) / 1024:.2f} KB")
        return True
    except Exception as e:
        print(f"❌ PCAP文件生成失败: {e}")
        return False


def analyze_generated_pcap(filename):
    """分析生成的PCAP文件"""
    if not SCAPY_AVAILABLE or not os.path.exists(filename):
        return

    print(f"\n📊 分析PCAP文件: {filename}")
    print("=" * 50)

    try:
        packets = rdpcap(filename)
        total_packets = len(packets)

        # 统计协议分布
        tcp_count = sum(1 for p in packets if TCP in p)
        udp_count = sum(1 for p in packets if UDP in p)
        icmp_count = sum(1 for p in packets if ICMP in p)

        # 统计端口分布
        common_ports = [80, 443, 22, 21, 25, 53, 67, 68, 123]
        common_port_count = 0
        high_port_count = 0

        for packet in packets:
            if TCP in packet:
                if (
                    packet[TCP].dport in common_ports
                    or packet[TCP].sport in common_ports
                ):
                    common_port_count += 1
                elif packet[TCP].dport > 10000 or packet[TCP].sport > 10000:
                    high_port_count += 1
            elif UDP in packet:
                if (
                    packet[UDP].dport in common_ports
                    or packet[UDP].sport in common_ports
                ):
                    common_port_count += 1
                elif packet[UDP].dport > 10000 or packet[UDP].sport > 10000:
                    high_port_count += 1

        # 统计IP地址
        src_ips = set()
        dst_ips = set()
        for packet in packets:
            if IP in packet:
                src_ips.add(packet[IP].src)
                dst_ips.add(packet[IP].dst)

        print(f"总包数: {total_packets}")
        print(f"协议分布:")
        print(f"  - TCP: {tcp_count} ({tcp_count/total_packets*100:.1f}%)")
        print(f"  - UDP: {udp_count} ({udp_count/total_packets*100:.1f}%)")
        print(f"  - ICMP: {icmp_count} ({icmp_count/total_packets*100:.1f}%)")
        print(f"端口分布:")
        print(
            f"  - 常见端口: {common_port_count} ({common_port_count/total_packets*100:.1f}%)"
        )
        print(
            f"  - 高端口 (>10000): {high_port_count} ({high_port_count/total_packets*100:.1f}%)"
        )
        print(f"IP地址统计:")
        print(f"  - 源IP数量: {len(src_ips)}")
        print(f"  - 目标IP数量: {len(dst_ips)}")

        # 显示部分源IP
        print(f"  - 源IP示例: {list(src_ips)[:5]}")
        print(f"  - 目标IP示例: {list(dst_ips)[:5]}")

    except Exception as e:
        print(f"❌ 分析失败: {e}")


if __name__ == "__main__":
    print("🔧 PCAP测试文件生成器")
    print("=" * 50)

    # 生成文件
    filename = "test_anomaly_traffic_500.pcap"
    success = generate_test_pcap(filename, 500)

    if success:
        # 分析生成的文件
        analyze_generated_pcap(filename)

        print(f"\n✅ 文件生成完成!")
        print(f"📁 文件路径: {os.path.abspath(filename)}")
        print(f"💡 可以直接在AI检测系统中上传此文件进行测试")
        print(f"🔍 此文件包含约30%的异常流量，用于测试检测能力")
    else:
        print("❌ 文件生成失败")
        print("💡 提示: 请确保已安装scapy库 (pip install scapy)")
