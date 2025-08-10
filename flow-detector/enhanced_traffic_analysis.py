#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强的流量分析模块 - 详细分类统计正常和恶意流量
"""

import pandas as pd
import numpy as np
from typing import Dict, List
from datetime import datetime
import os


def safe_column_access(df: pd.DataFrame, column: str, default_value=""):
    """安全访问DataFrame列，如果列不存在则返回默认值"""
    if column in df.columns:
        return df[column]
    else:
        return pd.Series([default_value] * len(df), index=df.index)


def enhanced_traffic_classification(df: pd.DataFrame) -> Dict:
    """
    增强的流量分类分析

    Args:
        df: 流量数据DataFrame

    Returns:
        详细分类结果字典
    """
    print("🔍 执行增强流量分类分析...")

    total_flows = len(df)

    # 1. 基本流量分类
    if "label" in df.columns:
        normal_traffic = df[df["label"] == "Normal"]
        malicious_traffic = df[df["label"] != "Normal"]
    else:
        normal_traffic = df
        malicious_traffic = pd.DataFrame()

    # 2. 正常流量细分
    normal_classification = classify_normal_traffic(normal_traffic)

    # 3. 恶意流量分析
    malicious_classification = classify_malicious_traffic(malicious_traffic)

    # 4. 威胁流量统一分类 - 避免重复计算
    threat_classification = classify_threat_traffic_unified(df, malicious_traffic)

    # 5. 构建详细结果
    threat_count = threat_classification["total_threat_flows"]
    malicious_count = threat_classification["confirmed_malicious"]
    suspicious_count = threat_classification["suspicious_anomalies"]
    normal_count = total_flows - threat_count  # 确保不重复计算

    result = {
        "timestamp": datetime.now().isoformat(),
        "total_flows": total_flows,
        "classification_summary": {
            "normal_flows": normal_count,
            "malicious_flows": malicious_count,
            "suspicious_flows": suspicious_count,
            "normal_percentage": (
                normal_count / total_flows * 100 if total_flows > 0 else 0
            ),
            "malicious_percentage": (
                malicious_count / total_flows * 100 if total_flows > 0 else 0
            ),
            "suspicious_percentage": (
                suspicious_count / total_flows * 100 if total_flows > 0 else 0
            ),
        },
        "normal_traffic_details": normal_classification,
        "malicious_traffic_details": threat_classification["malicious_details"],
        "suspicious_traffic_details": threat_classification["suspicious_details"],
        "export_data": {
            "malicious_flows": threat_classification["export_malicious"],
            "suspicious_flows": threat_classification["export_suspicious"],
        },
    }

    return result


def classify_threat_traffic_unified(
    df: pd.DataFrame, malicious_traffic: pd.DataFrame
) -> Dict:
    """
    统一分类威胁流量，避免恶意和可疑流量重复计算

    Args:
        df: 全部流量数据
        malicious_traffic: 已标记的恶意流量

    Returns:
        统一的威胁分类结果
    """
    # 1. 确认的恶意流量（有明确标签）
    confirmed_malicious = len(malicious_traffic)

    # 2. 在正常流量中检测可疑异常（统计异常但没有恶意标签）
    normal_flows = df[df["label"] == "Normal"] if "label" in df.columns else df
    suspicious_detection = detect_suspicious_traffic(normal_flows)
    suspicious_anomalies = suspicious_detection["suspicious_count"]

    # 3. 总威胁流量 = 确认恶意 + 可疑异常（不重复）
    total_threat_flows = confirmed_malicious + suspicious_anomalies

    # 4. 构建恶意流量详情
    malicious_details = classify_malicious_traffic(malicious_traffic)

    # 5. 构建导出数据
    export_malicious = []
    if len(malicious_traffic) > 0:
        for _, row in malicious_traffic.iterrows():
            export_malicious.append(
                {
                    "flow_id": row.get("id", ""),
                    "timestamp": datetime.now().isoformat(),
                    "protocol": row.get("proto", ""),
                    "service": row.get("service", ""),
                    "duration": row.get("dur", 0),
                    "src_bytes": row.get("sbytes", 0),
                    "dst_bytes": row.get("dbytes", 0),
                    "src_packets": row.get("spkts", 0),
                    "dst_packets": row.get("dpkts", 0),
                    "attack_type": row.get("attack_cat", "Unknown"),
                    "label": "Attack",
                    "threat_level": get_threat_level(row),
                }
            )

    return {
        "total_threat_flows": total_threat_flows,
        "confirmed_malicious": confirmed_malicious,
        "suspicious_anomalies": suspicious_anomalies,
        "malicious_details": malicious_details,
        "suspicious_details": suspicious_detection,
        "export_malicious": export_malicious,
        "export_suspicious": suspicious_detection.get("suspicious_flows", []),
    }


def classify_normal_traffic(df: pd.DataFrame) -> Dict:
    """分类正常流量"""
    if len(df) == 0:
        return {
            "http_traffic": {"count": 0, "percentage": 0, "details": {}},
            "dns_traffic": {"count": 0, "percentage": 0, "details": {}},
            "video_traffic": {"count": 0, "percentage": 0, "details": {}},
            "other_traffic": {"count": 0, "percentage": 0, "details": {}},
        }

    total_normal = len(df)

    # 检查必要的列是否存在，如果不存在则创建默认值
    service_col = safe_column_access(df, "service", "")
    proto_col = safe_column_access(df, "proto", "")

    # HTTP流量识别
    http_conditions = (
        (service_col.str.contains("http", case=False, na=False))
        | (proto_col == "tcp") & (service_col.isin(["http", "https", "www"]))
        | (df.get("ct_flw_http_mthd", 0) > 0)
    )
    http_traffic = df[http_conditions]

    # DNS流量识别
    dns_conditions = (
        (service_col.str.contains("dns", case=False, na=False))
        | (proto_col == "udp") & (service_col == "dns")
        | (proto_col == "udp")
        & (df.get("dpkts", 0) == df.get("spkts", 0))
        & (df.get("sbytes", 0) < 200)
    )
    dns_traffic = df[dns_conditions]

    # 视频流量识别（基于流量特征）
    video_conditions = (
        (service_col.str.contains("rtmp|rtsp|streaming", case=False, na=False))
        | (
            (df.get("sbytes", 0) > 10000)
            & (df.get("dur", 0) > 10)
            & (proto_col == "tcp")
        )
        | ((df.get("rate", 0) > 1000) & (df.get("sload", 0) > 5000))
    )
    video_traffic = df[video_conditions]

    # 其他流量
    identified_indices = (
        set(http_traffic.index) | set(dns_traffic.index) | set(video_traffic.index)
    )
    other_traffic = df[~df.index.isin(identified_indices)]

    return {
        "http_traffic": {
            "count": len(http_traffic),
            "percentage": (
                len(http_traffic) / total_normal * 100 if total_normal > 0 else 0
            ),
            "details": {
                "avg_duration": (
                    http_traffic["dur"].mean() if len(http_traffic) > 0 else 0
                ),
                "avg_bytes": (
                    (
                        http_traffic.get("sbytes", 0) + http_traffic.get("dbytes", 0)
                    ).mean()
                    if len(http_traffic) > 0
                    else 0
                ),
                "protocols": (
                    http_traffic["proto"].value_counts().to_dict()
                    if len(http_traffic) > 0
                    else {}
                ),
            },
        },
        "dns_traffic": {
            "count": len(dns_traffic),
            "percentage": (
                len(dns_traffic) / total_normal * 100 if total_normal > 0 else 0
            ),
            "details": {
                "avg_duration": (
                    dns_traffic["dur"].mean() if len(dns_traffic) > 0 else 0
                ),
                "avg_bytes": (
                    (dns_traffic.get("sbytes", 0) + dns_traffic.get("dbytes", 0)).mean()
                    if len(dns_traffic) > 0
                    else 0
                ),
                "query_patterns": (
                    safe_column_access(dns_traffic, "service", "")
                    .value_counts()
                    .head(5)
                    .to_dict()
                    if len(dns_traffic) > 0
                    else {}
                ),
            },
        },
        "video_traffic": {
            "count": len(video_traffic),
            "percentage": (
                len(video_traffic) / total_normal * 100 if total_normal > 0 else 0
            ),
            "details": {
                "avg_duration": (
                    video_traffic["dur"].mean() if len(video_traffic) > 0 else 0
                ),
                "avg_bytes": (
                    (
                        video_traffic.get("sbytes", 0) + video_traffic.get("dbytes", 0)
                    ).mean()
                    if len(video_traffic) > 0
                    else 0
                ),
                "high_bandwidth_flows": (
                    len(video_traffic[video_traffic.get("sbytes", 0) > 50000])
                    if len(video_traffic) > 0
                    else 0
                ),
            },
        },
        "other_traffic": {
            "count": len(other_traffic),
            "percentage": (
                len(other_traffic) / total_normal * 100 if total_normal > 0 else 0
            ),
            "details": {
                "services": (
                    safe_column_access(other_traffic, "service", "")
                    .value_counts()
                    .head(10)
                    .to_dict()
                    if len(other_traffic) > 0
                    else {}
                ),
                "protocols": (
                    other_traffic["proto"].value_counts().to_dict()
                    if len(other_traffic) > 0
                    else {}
                ),
            },
        },
    }


def classify_malicious_traffic(df: pd.DataFrame) -> Dict:
    """分类恶意流量"""
    if len(df) == 0:
        return {
            "attack_types": {},
            "severity_analysis": {},
            "threat_patterns": {},
            "export_ready_data": [],
        }

    # 攻击类型统计
    attack_types = {}
    if "attack_cat" in df.columns:
        attack_counts = df["attack_cat"].value_counts()
        for attack, count in attack_counts.items():
            attack_types[attack] = {
                "count": int(count),
                "percentage": float(count / len(df) * 100),
                "avg_duration": float(df[df["attack_cat"] == attack]["dur"].mean()),
                "avg_bytes": float(
                    (
                        df[df["attack_cat"] == attack].get("sbytes", 0)
                        + df[df["attack_cat"] == attack].get("dbytes", 0)
                    ).mean()
                ),
            }

    # 威胁级别分析
    severity_analysis = analyze_threat_severity(df)

    # 准备导出数据
    export_data = []
    for _, row in df.iterrows():
        export_data.append(
            {
                "flow_id": row.get("id", ""),
                "timestamp": datetime.now().isoformat(),
                "protocol": row.get("proto", ""),
                "service": row.get("service", ""),
                "duration": row.get("dur", 0),
                "src_bytes": row.get("sbytes", 0),
                "dst_bytes": row.get("dbytes", 0),
                "src_packets": row.get("spkts", 0),
                "dst_packets": row.get("dpkts", 0),
                "attack_type": row.get("attack_cat", "Unknown"),
                "label": row.get("label", "Attack"),
                "threat_level": get_threat_level(row),
            }
        )

    return {
        "attack_types": attack_types,
        "severity_analysis": severity_analysis,
        "threat_patterns": analyze_threat_patterns(df),
        "export_ready_data": export_data,
    }


def detect_suspicious_traffic(df: pd.DataFrame) -> Dict:
    """检测可疑流量（基于统计异常）"""
    from scipy import stats

    suspicious_flows = []
    suspicious_indices = []

    # 统计异常检测
    numeric_features = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate"]
    available_features = [f for f in numeric_features if f in df.columns]

    if available_features:
        feature_data = df[available_features].fillna(0)

        # 过滤有效特征
        valid_features = []
        for feature in available_features:
            if feature_data[feature].std() > 1e-8:
                valid_features.append(feature)

        if valid_features:
            valid_data = feature_data[valid_features]

            # 计算Z-score
            z_scores = np.abs(stats.zscore(valid_data, axis=0, nan_policy="omit"))
            z_scores = np.nan_to_num(z_scores, nan=0.0)

            # 检测异常
            threshold = 3.0
            anomaly_mask = (z_scores > threshold).any(axis=1)

            if anomaly_mask.any():
                suspicious_df = df[anomaly_mask]
                suspicious_indices = suspicious_df.index.tolist()

                # 准备可疑流量导出数据
                for idx, (_, row) in enumerate(suspicious_df.iterrows()):
                    # 找到在anomaly_mask中的对应位置
                    original_idx = np.where(anomaly_mask)[0][idx]
                    max_z_score = float(np.nanmax(z_scores[original_idx]))
                    suspicious_flows.append(
                        {
                            "flow_id": row.get("id", ""),
                            "timestamp": datetime.now().isoformat(),
                            "protocol": row.get("proto", ""),
                            "service": row.get("service", ""),
                            "duration": row.get("dur", 0),
                            "src_bytes": row.get("sbytes", 0),
                            "dst_bytes": row.get("dbytes", 0),
                            "src_packets": row.get("spkts", 0),
                            "dst_packets": row.get("dpkts", 0),
                            "anomaly_score": max_z_score,
                            "label": row.get("label", "Normal"),
                            "suspicion_reason": "Statistical Anomaly",
                        }
                    )

    return {
        "suspicious_count": len(suspicious_flows),
        "suspicious_flows": suspicious_flows,
        "detection_method": "Statistical Z-Score Analysis",
        "threshold_used": 3.0,
        "features_analyzed": valid_features if "valid_features" in locals() else [],
    }


def analyze_threat_severity(df: pd.DataFrame) -> Dict:
    """分析威胁严重程度"""
    if len(df) == 0:
        return {"high": 0, "medium": 0, "low": 0}

    severity_counts = {"high": 0, "medium": 0, "low": 0}

    for _, row in df.iterrows():
        level = get_threat_level(row)
        severity_counts[level] += 1

    total = len(df)
    return {
        "high": {
            "count": severity_counts["high"],
            "percentage": severity_counts["high"] / total * 100,
        },
        "medium": {
            "count": severity_counts["medium"],
            "percentage": severity_counts["medium"] / total * 100,
        },
        "low": {
            "count": severity_counts["low"],
            "percentage": severity_counts["low"] / total * 100,
        },
    }


def get_threat_level(row) -> str:
    """根据流量特征判断威胁级别"""
    attack_type = row.get("attack_cat", "Unknown")
    duration = row.get("dur", 0)
    bytes_total = row.get("sbytes", 0) + row.get("dbytes", 0)

    # 高威胁: DoS、Backdoor、高流量攻击
    if (
        attack_type in ["DoS", "Backdoor", "Exploit"]
        or bytes_total > 100000
        or duration > 30
    ):
        return "high"
    # 中等威胁: 侦察、暴力破解
    elif (
        attack_type in ["Reconnaissance", "Brute Force", "Analysis"]
        or bytes_total > 10000
    ):
        return "medium"
    # 低威胁: 其他
    else:
        return "low"


def analyze_threat_patterns(df: pd.DataFrame) -> Dict:
    """分析威胁模式"""
    if len(df) == 0:
        return {}

    patterns = {}

    # 协议分布
    if "proto" in df.columns:
        patterns["protocol_distribution"] = df["proto"].value_counts().to_dict()

    # 服务分布
    if "service" in df.columns:
        patterns["service_distribution"] = (
            safe_column_access(df, "service", "").value_counts().head(10).to_dict()
        )

    # 状态分布
    if "state" in df.columns:
        patterns["state_distribution"] = df["state"].value_counts().to_dict()

    return patterns


def generate_export_csv(
    malicious_data: List[Dict], suspicious_data: List[Dict], output_dir: str = "."
) -> str:
    """生成导出用的CSV文件"""

    # 合并恶意和可疑流量数据
    all_threat_data = []

    # 添加恶意流量
    for item in malicious_data:
        item["threat_category"] = "Malicious"
        all_threat_data.append(item)

    # 添加可疑流量
    for item in suspicious_data:
        item["threat_category"] = "Suspicious"
        all_threat_data.append(item)

    if not all_threat_data:
        return None

    # 创建DataFrame
    df_export = pd.DataFrame(all_threat_data)

    # 生成文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"threat_traffic_export_{timestamp}.csv"
    filepath = os.path.join(output_dir, filename)

    # 保存CSV
    df_export.to_csv(filepath, index=False, encoding="utf-8")

    print(f"✅ 威胁流量数据已导出到: {filepath}")
    return filepath


if __name__ == "__main__":
    # 测试代码
    print("🧪 测试增强流量分类功能...")

    # 查找可用的测试文件
    test_files = ["test_with_attacks.csv", "test_data.csv", "UNSW_NB15_testing-set.csv"]

    test_df = None
    for file in test_files:
        if os.path.exists(file):
            print(f"✅ 找到测试文件: {file}")
            test_df = pd.read_csv(file)
            break

    if test_df is None:
        print("⚠️ 未找到测试文件，创建模拟数据进行测试...")
        # 创建模拟测试数据
        test_df = pd.DataFrame(
            {
                "label": ["Normal"] * 80 + ["Attack"] * 20,
                "dur": np.random.exponential(10, 100),
                "sbytes": np.random.lognormal(8, 2, 100),
                "spkts": np.random.poisson(50, 100),
                "proto": np.random.choice(["tcp", "udp", "icmp"], 100),
            }
        )
        print(f"✅ 创建了包含 {len(test_df)} 条记录的模拟数据")

    result = enhanced_traffic_classification(test_df)

    print(f"总流量: {result['total_flows']}")
    print(
        f"正常流量: {result['classification_summary']['normal_flows']} ({result['classification_summary']['normal_percentage']:.1f}%)"
    )
    print(
        f"恶意流量: {result['classification_summary']['malicious_flows']} ({result['classification_summary']['malicious_percentage']:.1f}%)"
    )
    print(
        f"可疑流量: {result['classification_summary']['suspicious_flows']} ({result['classification_summary']['suspicious_percentage']:.1f}%)"
    )
