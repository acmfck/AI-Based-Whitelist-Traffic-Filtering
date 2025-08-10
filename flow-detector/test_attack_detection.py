#!/usr/bin/env python3
"""
分析包含攻击流量的测试CSV文件
"""

import pandas as pd
import numpy as np
from scipy import stats


def analyze_csv_with_attacks():
    """分析包含攻击流量的CSV文件数据"""
    try:
        # 读取包含攻击的测试数据
        df = pd.read_csv("test_with_attacks.csv")

        print("=== 包含攻击流量的测试数据分析 ===")
        print(f"总记录数: {len(df)}")
        print(f"总列数: {len(df.columns)}")
        print()

        # 分析标签分布
        print("=== 标签分布 ===")
        label_counts = df["label"].value_counts()
        for label, count in label_counts.items():
            percentage = (count / len(df)) * 100
            print(f"{label}: {count} ({percentage:.1f}%)")
        print()

        # 分析攻击类别分布
        print("=== 攻击类别分布 ===")
        if "attack_cat" in df.columns:
            attack_counts = df["attack_cat"].value_counts()
            for attack, count in attack_counts.items():
                percentage = (count / len(df)) * 100
                print(f"{attack}: {count} ({percentage:.1f}%)")
            print()

        # 查看攻击流量详情
        attack_traffic = df[df["label"] == "Attack"]
        print(f"攻击流量数: {len(attack_traffic)}")
        if len(attack_traffic) > 0:
            print("所有攻击流量详情:")
            cols_to_show = [
                "id",
                "dur",
                "proto",
                "service",
                "state",
                "attack_cat",
                "label",
                "spkts",
                "sbytes",
            ]
            print(attack_traffic[cols_to_show])
        print()

        # 正常流量统计
        normal_traffic = df[df["label"] == "Normal"]
        print(f"正常流量数: {len(normal_traffic)}")
        print()

        # 基本统计信息
        print("=== 基本统计信息 ===")
        print(f'平均持续时间: {df["dur"].mean():.3f}s')
        print(f'平均包数: {(df["spkts"] + df["dpkts"]).mean():.1f}')
        print(f'平均字节数: {(df["sbytes"] + df["dbytes"]).mean():.0f}')
        print(f'最大持续时间: {df["dur"].max():.3f}s')
        print(f'最大字节数: {max(df["sbytes"].max(), df["dbytes"].max()):.0f}')
        print()

        # 攻击流量vs正常流量对比
        print("=== 攻击 vs 正常流量对比 ===")
        if len(attack_traffic) > 0:
            print(f'攻击流量平均持续时间: {attack_traffic["dur"].mean():.3f}s')
            print(f'正常流量平均持续时间: {normal_traffic["dur"].mean():.3f}s')
            print(
                f'攻击流量平均包数: {(attack_traffic["spkts"] + attack_traffic["dpkts"]).mean():.1f}'
            )
            print(
                f'正常流量平均包数: {(normal_traffic["spkts"] + normal_traffic["dpkts"]).mean():.1f}'
            )
            print(
                f'攻击流量平均字节数: {(attack_traffic["sbytes"] + attack_traffic["dbytes"]).mean():.0f}'
            )
            print(
                f'正常流量平均字节数: {(normal_traffic["sbytes"] + normal_traffic["dbytes"]).mean():.0f}'
            )
            print()

        # Z-score异常检测
        print("=== Z-score异常检测 ===")
        feature_cols = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate"]
        available_cols = [col for col in feature_cols if col in df.columns]

        if available_cols:
            print(f"使用特征: {available_cols}")

            # 准备数据
            feature_data = df[available_cols].fillna(0)

            # 过滤掉标准差为0的特征（避免除零错误）
            valid_cols = []
            for col in available_cols:
                if feature_data[col].std() > 1e-8:  # 避免标准差接近0
                    valid_cols.append(col)
                else:
                    print(f"跳过特征 {col}（标准差为0或接近0）")

            if valid_cols:
                print(f"有效特征: {valid_cols}")
                valid_data = feature_data[valid_cols]

                # 计算Z-score
                z_scores = np.abs(stats.zscore(valid_data, axis=0, nan_policy="omit"))

                # 设置阈值（3-sigma规则）
                threshold = 3.0
                anomaly_mask = (z_scores > threshold).any(axis=1)

                anomalies = df[anomaly_mask]
                print(
                    f"Z-score检测到异常数量: {len(anomalies)} / {len(df)} "
                    f"({len(anomalies)/len(df)*100:.2f}%)"
                )

                if len(anomalies) > 0:
                    print("异常样本分类:")
                    anomaly_labels = anomalies["label"].value_counts()
                    for label, count in anomaly_labels.items():
                        percentage = (count / len(anomalies)) * 100
                        print(f"  {label}: {count} ({percentage:.1f}%)")

                    print("\n前10个异常样本:")
                    cols_to_show = [
                        "id",
                        "dur",
                        "proto",
                        "service",
                        "attack_cat",
                        "label",
                        "spkts",
                        "sbytes",
                    ]
                    print(anomalies[cols_to_show].head(10))

                    # 显示这些异常样本的最大Z-score
                    print("\n异常样本的最大Z-score值:")
                    max_z_scores = np.nanmax(z_scores[anomaly_mask], axis=1)
                    for i, (idx, z_score) in enumerate(
                        zip(anomalies.index[:10], max_z_scores[:10])
                    ):
                        sample_id = anomalies.iloc[i]["id"]
                        sample_label = anomalies.iloc[i]["label"]
                        sample_attack = anomalies.iloc[i]["attack_cat"]
                        print(
                            f"样本{sample_id} ({sample_label}-{sample_attack}): 最大Z-score = {z_score:.3f}"
                        )
                else:
                    print("未检测到异常样本（Z-score < 3.0）")
            else:
                print("没有有效的特征进行异常检测（所有特征标准差为0）")
        else:
            print("没有足够的数值特征进行异常检测")

        # 攻击检测准确率评估
        if len(attack_traffic) > 0 and "anomalies" in locals():
            print("\n=== 攻击检测准确率评估 ===")
            detected_attacks = anomalies[anomalies["label"] == "Attack"]
            missed_attacks = attack_traffic[~attack_traffic.index.isin(anomalies.index)]
            false_positives = anomalies[anomalies["label"] == "Normal"]

            print(f"真实攻击数量: {len(attack_traffic)}")
            print(f"检测到的攻击数量: {len(detected_attacks)}")
            print(f"漏检的攻击数量: {len(missed_attacks)}")
            print(f"误报数量（正常被标记为异常）: {len(false_positives)}")

            if len(attack_traffic) > 0:
                detection_rate = len(detected_attacks) / len(attack_traffic) * 100
                print(f"攻击检测率: {detection_rate:.1f}%")

            if len(anomalies) > 0:
                precision = len(detected_attacks) / len(anomalies) * 100
                print(f"检测精确度: {precision:.1f}%")

        return len(anomalies) if "anomalies" in locals() else 0, len(attack_traffic)

    except Exception as e:
        print(f"分析失败: {e}")
        import traceback

        traceback.print_exc()
        return 0, 0


if __name__ == "__main__":
    anomaly_count, attack_count = analyze_csv_with_attacks()
    print(f"\n=== 总结 ===")
    print(f"真实攻击流量数量: {attack_count}")
    print(f"基于Z-score的异常检测结果: {anomaly_count} 个异常样本")
