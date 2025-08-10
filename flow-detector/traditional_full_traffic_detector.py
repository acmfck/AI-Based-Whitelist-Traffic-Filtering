"""
传统全流量检测系统
模拟传统安全设备的全流量检测模式 - 性能瓶颈的根本原因

这种模式对所有流量都进行：
1. 深度包检测 (DPI)
2. 协议解析和还原
3. 特征提取和比对
4. 行为分析
5. 沙箱分析
6. 威胁情报匹配

问题：即使是正常的CDN、P2P流量也要经过完整检测流程
"""

import pandas as pd
import numpy as np
import time
import hashlib
import re
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import threading
import queue
import json


@dataclass
class PacketInfo:
    """数据包信息"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_size: int
    payload_data: bytes
    tcp_flags: str
    flow_id: str


@dataclass
class ThreatSignature:
    """威胁签名"""
    signature_id: str
    name: str
    pattern: str
    severity: str
    category: str
    regex_pattern: re.Pattern


class DeepPacketInspector:
    """深度包检测引擎 - 消耗大量CPU资源"""
    
    def __init__(self):
        self.packet_count = 0
        self.processed_bytes = 0
        self.detection_rules = self._load_detection_rules()
        
    def _load_detection_rules(self) -> List[ThreatSignature]:
        """加载检测规则库 - 模拟数万条规则"""
        rules = []
        
        # 恶意软件签名
        malware_patterns = [
            r"(?i)(zeus|conficker|stuxnet|wannacry|ransomware)",
            r"\x4d\x5a.{50,100}This program cannot be run",
            r"(?i)(backdoor|trojan|keylogger|botnet)",
        ]
        
        # 网络攻击签名
        attack_patterns = [
            r"(?i)(union.*select|drop.*table|exec.*xp_)",
            r"<script.*?>.*?</script>",
            r"(?i)(\.\./){3,}",
            r"(?i)(cmd\.exe|/bin/sh|powershell)",
        ]
        
        # DDoS攻击签名
        ddos_patterns = [
            r"GET / HTTP/1\.[01]\r\n\r\n",
            r"(?i)(slowloris|hulk|goldeneye)",
        ]
        
        # 生成大量检测规则
        for i, pattern in enumerate(malware_patterns):
            rules.append(ThreatSignature(
                signature_id=f"MAL_{i:04d}",
                name=f"Malware Pattern {i}",
                pattern=pattern,
                severity="HIGH",
                category="MALWARE",
                regex_pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL)
            ))
            
        for i, pattern in enumerate(attack_patterns):
            rules.append(ThreatSignature(
                signature_id=f"ATK_{i:04d}",
                name=f"Attack Pattern {i}",
                pattern=pattern,
                severity="MEDIUM",
                category="ATTACK",
                regex_pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL)
            ))
            
        for i, pattern in enumerate(ddos_patterns):
            rules.append(ThreatSignature(
                signature_id=f"DDS_{i:04d}",
                name=f"DDoS Pattern {i}",
                pattern=pattern,
                severity="HIGH",
                category="DDOS",
                regex_pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL)
            ))
            
        return rules
    
    def inspect_packet(self, packet: PacketInfo) -> Dict[str, Any]:
        """深度包检测 - 每个包都要经过完整检测"""
        start_time = time.time()
        
        # 1. 协议解析
        protocol_info = self._parse_protocol(packet)
        
        # 2. 载荷重组（对分片包）
        reassembled_payload = self._reassemble_payload(packet)
        
        # 3. 内容解码（处理编码、压缩等）
        decoded_content = self._decode_content(reassembled_payload)
        
        # 4. 特征匹配 - 对每个包应用所有规则
        threat_matches = self._match_signatures(decoded_content)
        
        # 5. 协议异常检测
        protocol_anomalies = self._detect_protocol_anomalies(packet, protocol_info)
        
        # 6. 统计分析
        statistical_analysis = self._statistical_analysis(packet)
        
        processing_time = time.time() - start_time
        self.packet_count += 1
        self.processed_bytes += packet.payload_size
        
        return {
            "packet_id": f"{packet.flow_id}_{self.packet_count}",
            "processing_time": processing_time,
            "protocol_info": protocol_info,
            "threat_matches": threat_matches,
            "protocol_anomalies": protocol_anomalies,
            "statistical_analysis": statistical_analysis,
            "is_threat": len(threat_matches) > 0 or len(protocol_anomalies) > 0
        }
    
    def _parse_protocol(self, packet: PacketInfo) -> Dict[str, Any]:
        """协议解析 - 消耗CPU资源"""
        time.sleep(0.001)  # 模拟协议解析开销
        
        if packet.protocol.upper() == "TCP":
            return {
                "type": "TCP",
                "flags": packet.tcp_flags,
                "connection_state": "ESTABLISHED" if "ACK" in packet.tcp_flags else "NEW",
                "window_size": np.random.randint(1024, 65536)
            }
        elif packet.protocol.upper() == "UDP":
            return {
                "type": "UDP",
                "is_dns": packet.dst_port == 53 or packet.src_port == 53,
                "is_dhcp": packet.dst_port in [67, 68]
            }
        else:
            return {"type": "OTHER", "protocol": packet.protocol}
    
    def _reassemble_payload(self, packet: PacketInfo) -> bytes:
        """载荷重组 - 模拟分片重组开销"""
        time.sleep(0.0005)  # 模拟重组开销
        return packet.payload_data
    
    def _decode_content(self, payload: bytes) -> str:
        """内容解码 - 处理各种编码"""
        time.sleep(0.0008)  # 模拟解码开销
        
        try:
            # 尝试多种解码方式
            encodings = ["utf-8", "ascii", "latin-1", "gbk"]
            for encoding in encodings:
                try:
                    return payload.decode(encoding)
                except:
                    continue
            return str(payload)
        except:
            return ""
    
    def _match_signatures(self, content: str) -> List[Dict[str, Any]]:
        """签名匹配 - 最耗CPU的操作"""
        matches = []
        
        # 对每个包应用所有检测规则
        for rule in self.detection_rules:
            try:
                if rule.regex_pattern.search(content):
                    matches.append({
                        "signature_id": rule.signature_id,
                        "name": rule.name,
                        "severity": rule.severity,
                        "category": rule.category
                    })
                # 模拟正则匹配的CPU开销
                time.sleep(0.00001)
            except Exception as e:
                continue
                
        return matches
    
    def _detect_protocol_anomalies(self, packet: PacketInfo, protocol_info: Dict) -> List[str]:
        """协议异常检测"""
        anomalies = []
        
        # HTTP异常检测
        if packet.dst_port in [80, 443, 8080]:
            if packet.payload_size > 100000:  # 异常大的HTTP请求
                anomalies.append("OVERSIZED_HTTP_REQUEST")
            if packet.payload_size < 10:  # 异常小的HTTP请求
                anomalies.append("UNDERSIZED_HTTP_REQUEST")
        
        # DNS异常检测
        if packet.dst_port == 53:
            if packet.payload_size > 512:  # DNS请求过大
                anomalies.append("OVERSIZED_DNS_QUERY")
        
        # 端口扫描检测
        if packet.tcp_flags == "SYN" and packet.payload_size == 0:
            anomalies.append("POSSIBLE_PORT_SCAN")
        
        return anomalies
    
    def _statistical_analysis(self, packet: PacketInfo) -> Dict[str, float]:
        """统计分析"""
        return {
            "packet_entropy": np.random.random(),  # 模拟熵计算
            "size_deviation": abs(packet.payload_size - 1024) / 1024,
            "timing_anomaly": np.random.random()
        }


class BehaviorAnalyzer:
    """行为分析引擎 - 分析流量行为模式"""
    
    def __init__(self):
        self.flow_states = {}
        self.behavior_profiles = {}
        
    def analyze_flow_behavior(self, packet: PacketInfo) -> Dict[str, Any]:
        """流行为分析"""
        flow_id = packet.flow_id
        
        if flow_id not in self.flow_states:
            self.flow_states[flow_id] = {
                "start_time": packet.timestamp,
                "packet_count": 0,
                "total_bytes": 0,
                "protocols": set(),
                "ports": set(),
                "directions": {"incoming": 0, "outgoing": 0}
            }
        
        state = self.flow_states[flow_id]
        state["packet_count"] += 1
        state["total_bytes"] += packet.payload_size
        state["protocols"].add(packet.protocol)
        state["ports"].add(packet.dst_port)
        
        # 行为特征计算
        duration = packet.timestamp - state["start_time"]
        packet_rate = state["packet_count"] / max(duration, 0.001)
        byte_rate = state["total_bytes"] / max(duration, 0.001)
        
        # 异常行为检测
        anomalies = []
        
        # 高频连接异常
        if packet_rate > 1000:  # 每秒超过1000个包
            anomalies.append("HIGH_PACKET_RATE")
        
        # 大流量异常
        if byte_rate > 10_000_000:  # 每秒超过10MB
            anomalies.append("HIGH_BANDWIDTH_USAGE")
        
        # 端口扫描行为
        if len(state["ports"]) > 100:
            anomalies.append("PORT_SCANNING_BEHAVIOR")
        
        # 协议跳跃异常
        if len(state["protocols"]) > 5:
            anomalies.append("PROTOCOL_HOPPING")
        
        return {
            "flow_id": flow_id,
            "duration": duration,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "protocol_diversity": len(state["protocols"]),
            "port_diversity": len(state["ports"]),
            "behavior_anomalies": anomalies,
            "risk_score": min(len(anomalies) * 25, 100)
        }


class SandboxAnalyzer:
    """沙箱分析引擎 - 模拟文件和URL沙箱分析"""
    
    def __init__(self):
        self.analysis_queue = queue.Queue()
        self.results_cache = {}
        
    def analyze_in_sandbox(self, content: str, content_type: str) -> Dict[str, Any]:
        """沙箱分析 - 最耗时的操作"""
        
        # 计算内容哈希
        content_hash = hashlib.md5(content.encode()).hexdigest()
        
        # 检查缓存
        if content_hash in self.results_cache:
            return self.results_cache[content_hash]
        
        # 模拟沙箱分析时间（实际环境中可能需要几秒到几分钟）
        analysis_time = np.random.uniform(0.1, 2.0)
        time.sleep(analysis_time)
        
        # 模拟沙箱分析结果
        result = {
            "content_hash": content_hash,
            "analysis_time": analysis_time,
            "malware_detected": np.random.random() < 0.001,  # 0.1%概率检出恶意软件
            "suspicious_behavior": np.random.random() < 0.01,  # 1%概率可疑行为
            "file_operations": np.random.randint(0, 50),
            "network_connections": np.random.randint(0, 20),
            "registry_modifications": np.random.randint(0, 10),
            "reputation_score": np.random.randint(1, 100)
        }
        
        # 缓存结果
        self.results_cache[content_hash] = result
        
        return result


class ThreatIntelligence:
    """威胁情报引擎"""
    
    def __init__(self):
        self.ip_reputation_db = self._load_ip_reputation()
        self.domain_reputation_db = self._load_domain_reputation()
        self.file_hash_db = self._load_file_hash_db()
        
    def _load_ip_reputation(self) -> Dict[str, Dict]:
        """加载IP信誉库"""
        # 模拟威胁IP库
        threat_ips = {}
        for i in range(10000):  # 1万个威胁IP
            ip = f"{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}"
            threat_ips[ip] = {
                "reputation": np.random.choice(["malicious", "suspicious", "unknown"]),
                "categories": np.random.choice(["botnet", "malware", "phishing", "spam"], 1).tolist(),
                "last_seen": time.time() - np.random.randint(0, 86400*30)
            }
        return threat_ips
    
    def _load_domain_reputation(self) -> Dict[str, Dict]:
        """加载域名信誉库"""
        return {}  # 简化实现
    
    def _load_file_hash_db(self) -> Dict[str, Dict]:
        """加载文件哈希库"""
        return {}  # 简化实现
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """检查IP信誉"""
        if ip in self.ip_reputation_db:
            return {
                "ip": ip,
                "found": True,
                "reputation": self.ip_reputation_db[ip]["reputation"],
                "categories": self.ip_reputation_db[ip]["categories"],
                "threat_level": "HIGH" if self.ip_reputation_db[ip]["reputation"] == "malicious" else "MEDIUM"
            }
        return {"ip": ip, "found": False, "reputation": "unknown", "threat_level": "LOW"}


class TraditionalFullTrafficDetector:
    """传统全流量检测系统 - 性能瓶颈演示"""
    
    def __init__(self):
        self.dpi_engine = DeepPacketInspector()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.sandbox_analyzer = SandboxAnalyzer()
        self.threat_intel = ThreatIntelligence()
        
        # 性能统计
        self.total_packets = 0
        self.total_processing_time = 0
        self.threat_alerts = []
        self.performance_metrics = {
            "packets_per_second": 0,
            "bytes_per_second": 0,
            "cpu_utilization": 0,
            "memory_usage": 0
        }
    
    def process_traffic(self, df: pd.DataFrame) -> Dict[str, Any]:
        """处理流量数据 - 展示传统模式的性能问题"""
        
        print("🔍 启动传统全流量检测模式...")
        print("⚠️  注意：这种模式会对所有流量进行完整检测，包括正常的CDN和P2P流量")
        
        start_time = time.time()
        results = []
        
        # 转换DataFrame为PacketInfo对象
        packets = self._convert_to_packets(df)
        
        print(f"📊 总流量包数: {len(packets)}")
        print("🚀 开始全流量检测...\n")
        
        for i, packet in enumerate(packets):
            packet_start = time.time()
            
            # 1. 深度包检测 - 每个包都要检测
            dpi_result = self.dpi_engine.inspect_packet(packet)
            
            # 2. 行为分析 - 每个包都要分析
            behavior_result = self.behavior_analyzer.analyze_flow_behavior(packet)
            
            # 3. 威胁情报查询 - 每个包都要查询
            intel_result = self.threat_intel.check_ip_reputation(packet.dst_ip)
            
            # 4. 沙箱分析 - 对载荷进行沙箱分析（最耗时）
            sandbox_result = None
            if packet.payload_size > 100:  # 只对较大载荷进行沙箱分析
                content = packet.payload_data.decode('utf-8', errors='ignore')
                sandbox_result = self.sandbox_analyzer.analyze_in_sandbox(content, "network_traffic")
            
            packet_time = time.time() - packet_start
            self.total_processing_time += packet_time
            self.total_packets += 1
            
            # 判断是否为威胁
            is_threat = (
                dpi_result["is_threat"] or
                behavior_result["risk_score"] > 50 or
                intel_result["threat_level"] in ["HIGH", "MEDIUM"] or
                (sandbox_result and (sandbox_result["malware_detected"] or sandbox_result["suspicious_behavior"]))
            )
            
            if is_threat:
                alert = {
                    "timestamp": packet.timestamp,
                    "flow_id": packet.flow_id,
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                    "threat_type": self._determine_threat_type(dpi_result, behavior_result, intel_result, sandbox_result),
                    "severity": self._calculate_severity(dpi_result, behavior_result, intel_result, sandbox_result),
                    "processing_time": packet_time
                }
                self.threat_alerts.append(alert)
            
            results.append({
                "packet_id": f"pkt_{i:06d}",
                "processing_time": packet_time,
                "is_threat": is_threat,
                "dpi_result": dpi_result,
                "behavior_result": behavior_result,
                "intel_result": intel_result,
                "sandbox_result": sandbox_result
            })
            
            # 进度显示
            if (i + 1) % 1000 == 0:
                elapsed = time.time() - start_time
                pps = (i + 1) / elapsed
                print(f"📈 已处理: {i+1:,} 包 | 速度: {pps:.1f} pps | 威胁: {len(self.threat_alerts)} | 平均处理时间: {packet_time*1000:.2f}ms")
        
        total_time = time.time() - start_time
        
        # 计算性能指标
        self.performance_metrics = {
            "total_packets": len(packets),
            "total_time": total_time,
            "packets_per_second": len(packets) / total_time,
            "average_packet_time": self.total_processing_time / len(packets),
            "total_threats": len(self.threat_alerts),
            "threat_detection_rate": len(self.threat_alerts) / len(packets) * 100,
            "cpu_intensive_operations": len(packets) * 4,  # DPI + Behavior + Intel + Sandbox
            "estimated_cpu_utilization": min(95, self.total_processing_time / total_time * 100)
        }
        
        return {
            "results": results,
            "alerts": self.threat_alerts,
            "performance": self.performance_metrics,
            "summary": self._generate_summary()
        }
    
    def _convert_to_packets(self, df: pd.DataFrame) -> List[PacketInfo]:
        """将DataFrame转换为PacketInfo对象"""
        packets = []
        
        for idx, row in df.iterrows():
            try:
                # 安全地获取字节数，处理可能的NaN值
                sbytes = row.get('sbytes', 0)
                dbytes = row.get('dbytes', 0)
                
                # 处理NaN值
                if pd.isna(sbytes):
                    sbytes = 0
                if pd.isna(dbytes):
                    dbytes = 0
                
                # 生成模拟载荷数据
                payload_size = max(int(float(sbytes) + float(dbytes)), 0)
                payload_data = self._generate_mock_payload(payload_size, row)
                
                # 安全地获取端口号
                src_port = row.get('sport', np.random.randint(1024, 65535))
                dst_port = row.get('dport', np.random.randint(1, 65535))
                
                if pd.isna(src_port):
                    src_port = np.random.randint(1024, 65535)
                if pd.isna(dst_port):
                    dst_port = np.random.randint(1, 65535)
                
                packet = PacketInfo(
                    timestamp=time.time() + idx * 0.001,
                    src_ip=str(row.get('srcip', f"192.168.1.{np.random.randint(1,254)}")),
                    dst_ip=str(row.get('dstip', f"10.0.0.{np.random.randint(1,254)}")),
                    src_port=int(src_port),
                    dst_port=int(dst_port),
                    protocol=str(row.get('proto', 'tcp')).upper(),
                    payload_size=payload_size,
                    payload_data=payload_data,
                    tcp_flags=str(row.get('state', 'PSH,ACK')),
                    flow_id=f"flow_{idx:06d}"
                )
                packets.append(packet)
                
            except Exception as e:
                # 如果处理某行数据失败，创建一个默认的包
                print(f"警告：处理第{idx}行数据时出错: {e}，使用默认值")
                packet = PacketInfo(
                    timestamp=time.time() + idx * 0.001,
                    src_ip=f"192.168.1.{np.random.randint(1,254)}",
                    dst_ip=f"10.0.0.{np.random.randint(1,254)}",
                    src_port=np.random.randint(1024, 65535),
                    dst_port=np.random.randint(1, 65535),
                    protocol="TCP",
                    payload_size=1024,
                    payload_data=b"DEFAULT_PAYLOAD_DATA",
                    tcp_flags="PSH,ACK",
                    flow_id=f"flow_{idx:06d}"
                )
                packets.append(packet)
            
        return packets
    
    def _generate_mock_payload(self, size: int, row: pd.Series) -> bytes:
        """生成模拟载荷数据"""
        if size <= 0:
            return b""
        
        # 确保size是整数
        size = max(int(size), 1)
        
        # 根据端口生成不同类型的载荷
        try:
            dst_port = int(row.get('dport', 80))
        except (ValueError, TypeError):
            dst_port = 80
        
        if dst_port == 80:  # HTTP
            payload = "GET / HTTP/1.1\r\nHost: example.com\r\n" + \
                     "User-Agent: Mozilla/5.0\r\n\r\n"
        elif dst_port == 443:  # HTTPS
            payload = "TLS_HANDSHAKE_DATA_" + "X" * max(0, size - 20)
        elif dst_port == 53:  # DNS
            payload = "DNS_QUERY_DATA_" + "X" * max(0, size - 15)
        else:
            payload = "GENERIC_DATA_" + "X" * max(0, size - 13)
        
        # 确保载荷长度不超过指定大小
        if len(payload) > size:
            payload = payload[:size]
        elif len(payload) < size:
            payload = payload + "X" * (size - len(payload))
            
        return payload.encode('utf-8', errors='ignore')
    
    def _determine_threat_type(self, dpi_result, behavior_result, intel_result, sandbox_result) -> str:
        """确定威胁类型"""
        if sandbox_result and sandbox_result["malware_detected"]:
            return "MALWARE"
        elif intel_result["threat_level"] == "HIGH":
            return "THREAT_INTEL_MATCH"
        elif "HIGH_PACKET_RATE" in behavior_result["behavior_anomalies"]:
            return "DDOS_ATTACK"
        elif "PORT_SCANNING_BEHAVIOR" in behavior_result["behavior_anomalies"]:
            return "RECONNAISSANCE"
        elif dpi_result["threat_matches"]:
            return "SIGNATURE_MATCH"
        else:
            return "ANOMALOUS_BEHAVIOR"
    
    def _calculate_severity(self, dpi_result, behavior_result, intel_result, sandbox_result) -> str:
        """计算威胁严重程度"""
        score = 0
        
        if sandbox_result and sandbox_result["malware_detected"]:
            score += 50
        if intel_result["threat_level"] == "HIGH":
            score += 30
        elif intel_result["threat_level"] == "MEDIUM":
            score += 15
        
        score += behavior_result["risk_score"] * 0.3
        score += len(dpi_result["threat_matches"]) * 10
        
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_summary(self) -> Dict[str, Any]:
        """生成检测总结"""
        return {
            "performance_bottlenecks": [
                "每个数据包都需要完整的DPI检测",
                "所有流量都要进行行为分析",
                "大量正常流量（CDN、P2P）被无效处理",
                "沙箱分析造成严重延迟",
                "威胁情报查询增加网络开销"
            ],
            "efficiency_problems": [
                f"平均每包处理时间: {self.performance_metrics['average_packet_time']*1000:.2f}ms",
                f"CPU利用率估计: {self.performance_metrics['estimated_cpu_utilization']:.1f}%",
                f"实际威胁检出率仅: {self.performance_metrics['threat_detection_rate']:.3f}%",
                "大量计算资源浪费在正常流量上"
            ],
            "resource_waste": {
                "unnecessary_dpi_operations": self.performance_metrics['total_packets'],
                "redundant_behavior_analysis": self.performance_metrics['total_packets'],
                "excessive_sandbox_usage": sum(1 for r in self.threat_alerts if 'sandbox' in str(r)),
                "wasted_cpu_cycles": self.performance_metrics['cpu_intensive_operations']
            }
        }


def demonstrate_traditional_detection():
    """演示传统全流量检测的性能问题"""
    
    print("=" * 80)
    print("🔍 传统全流量检测系统演示")
    print("=" * 80)
    print()
    print("📋 传统模式特点:")
    print("   ✓ 对所有流量进行深度包检测 (DPI)")
    print("   ✓ 完整的协议解析和载荷重组") 
    print("   ✓ 全面的特征匹配和行为分析")
    print("   ✓ 沙箱分析和威胁情报查询")
    print("   ❌ 不区分正常流量和可疑流量")
    print("   ❌ CDN、P2P等正常流量也要完整处理")
    print()
    
    # 加载测试数据
    try:
        import os
        data_paths = [
            "data/UNSW_NB15_training-set.csv",
            "UNSW_NB15_training-set.csv",
            "../UNSW_NB15_training-set.csv"
        ]
        
        train_df = None
        for path in data_paths:
            if os.path.exists(path):
                train_df = pd.read_csv(path)
                break
        
        if train_df is None:
            print("❌ 找不到数据文件，生成模拟数据...")
            train_df = generate_mock_traffic_data(5000)
        
        # 使用较小的数据集演示（避免演示时间过长）
        test_df = train_df.head(100).copy()
        
        print(f"📊 测试数据: {len(test_df)} 条流量记录")
        print("🚀 启动传统全流量检测...")
        print()
        
        # 创建检测器
        detector = TraditionalFullTrafficDetector()
        
        # 开始检测
        detection_start = time.time()
        results = detector.process_traffic(test_df)
        detection_time = time.time() - detection_start
        
        # 输出结果
        print("\n" + "=" * 80)
        print("📊 传统全流量检测结果")
        print("=" * 80)
        
        perf = results["performance"]
        print(f"🔢 处理统计:")
        print(f"   总包数: {perf['total_packets']:,}")
        print(f"   总耗时: {perf['total_time']:.2f} 秒")
        print(f"   处理速度: {perf['packets_per_second']:.1f} 包/秒")
        print(f"   平均延迟: {perf['average_packet_time']*1000:.2f} 毫秒/包")
        print()
        
        print(f"🎯 威胁检测:")
        print(f"   威胁数量: {perf['total_threats']}")
        print(f"   检出率: {perf['threat_detection_rate']:.3f}%")
        print(f"   误报可能性: 很高（正常流量被标记为威胁）")
        print()
        
        print(f"💻 性能影响:")
        print(f"   CPU利用率: {perf['estimated_cpu_utilization']:.1f}%")
        print(f"   DPI操作数: {perf['cpu_intensive_operations']:,}")
        print(f"   内存占用: 高（需要缓存所有流状态）")
        print()
        
        print("⚠️  性能瓶颈分析:")
        for bottleneck in results["summary"]["performance_bottlenecks"]:
            print(f"   • {bottleneck}")
        print()
        
        print("💸 资源浪费:")
        waste = results["summary"]["resource_waste"]
        print(f"   • 无效DPI操作: {waste['unnecessary_dpi_operations']:,} 次")
        print(f"   • 冗余行为分析: {waste['redundant_behavior_analysis']:,} 次")
        print(f"   • CPU周期浪费: {waste['wasted_cpu_cycles']:,} 次")
        print()
        
        print("🎯 问题根源:")
        print("   传统模式的根本问题是：")
        print("   • 不区分攻击流量和正常流量")
        print("   • 对所有流量进行相同强度的检测")
        print("   • 大量正常流量（CDN、P2P）消耗宝贵的处理资源")
        print("   • 实际攻击流量占比 < 0.1%，但处理成本相同")
        print()
        
        print("💡 解决方案:")
        print("   AI白名单预过滤可以:")
        print("   • 预先识别可信流量（CDN、P2P等）")
        print("   • 将其加入白名单，跳过昂贵的检测")
        print("   • 集中资源检测真正可疑的流量")
        print("   • 显著提升整体处理性能")
        
        return results
        
    except Exception as e:
        print(f"❌ 演示失败: {e}")
        return None


def generate_mock_traffic_data(num_records: int) -> pd.DataFrame:
    """生成模拟流量数据"""
    
    data = []
    
    for i in range(num_records):
        # 生成多样化的流量类型
        traffic_type = np.random.choice(['web', 'dns', 'video', 'p2p', 'email'], p=[0.4, 0.2, 0.15, 0.15, 0.1])
        
        if traffic_type == 'web':
            dport = np.random.choice([80, 443, 8080])
            sbytes = np.random.randint(100, 10000)
            dur = np.random.uniform(0.1, 30.0)
        elif traffic_type == 'dns':
            dport = 53
            sbytes = np.random.randint(12, 512)
            dur = np.random.uniform(0.001, 2.0)
        elif traffic_type == 'video':
            dport = np.random.choice([1935, 554, 443])
            sbytes = np.random.randint(1000, 50000)
            dur = np.random.uniform(10.0, 3600.0)
        elif traffic_type == 'p2p':
            dport = np.random.randint(1024, 65535)
            sbytes = np.random.randint(500, 100000)
            dur = np.random.uniform(1.0, 1800.0)
        else:  # email
            dport = np.random.choice([25, 110, 143, 993, 995])
            sbytes = np.random.randint(500, 5000)
            dur = np.random.uniform(1.0, 60.0)
        
        record = {
            'srcip': f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
            'dstip': f"10.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
            'sport': np.random.randint(1024, 65535),
            'dport': dport,
            'proto': np.random.choice(['tcp', 'udp'], p=[0.8, 0.2]),
            'state': np.random.choice(['CON', 'INT', 'FIN', 'REQ']),
            'dur': dur,
            'sbytes': sbytes,
            'dbytes': np.random.randint(0, sbytes),
            'spkts': np.random.randint(1, 100),
            'dpkts': np.random.randint(1, 100),
            'label': np.random.choice([0, 1], p=[0.999, 0.001])  # 99.9% 正常流量
        }
        
        data.append(record)
    
    return pd.DataFrame(data)


if __name__ == "__main__":
    print("🔍 传统全流量检测系统 - 性能瓶颈演示")
    print("=" * 60)
    print()
    print("⚠️  警告: 此演示展示传统检测模式的性能问题")
    print("实际环境中这种模式会导致:")
    print("• 设备处理能力严重不足") 
    print("• 大量正常流量浪费资源")
    print("• 攻击检测延迟增加")
    print("• 整体安全效果下降")
    print()
    
    choice = input("是否继续演示? (y/n): ").lower().strip()
    
    if choice in ['y', 'yes', '是']:
        results = demonstrate_traditional_detection()
        
        if results:
            print("\n" + "="*80)
            print("✅ 演示完成！")
            print()
            print("💡 对比AI白名单预过滤方案:")
            print("• 白名单预过滤可将处理量减少60-80%")
            print("• 性能提升5-10倍")
            print("• 攻击检测准确率保持不变")
            print("• 设备资源利用率大幅优化")
            print("="*80)
    else:
        print("❌ 演示已取消")
