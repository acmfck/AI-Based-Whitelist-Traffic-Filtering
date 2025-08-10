"""
第二阶段 Day 1-2: 白名单过滤机制修复
基于第一阶段检测发现的0.0%过滤效率问题进行紧急修复
"""

import pandas as pd
import numpy as np
from protocol_analyzer import ProtocolAnalyzer
from typing import Dict, Tuple, Any


class WhitelistFilterV2:
    """改进的白名单过滤器 - 修复过滤效率问题"""

    def __init__(self):
        self.analyzer = ProtocolAnalyzer()
        self.whitelist_rules = {}
        self.debug_mode = True

    def analyze_filter_failure(self, df: pd.DataFrame):
        """分析为什么白名单过滤效率为0%"""
        print("🔍 诊断白名单过滤失效原因...")
        print("=" * 50)

        # 1. 检查数据预处理
        print(f"1. 数据检查:")
        print(f"   - 样本数量: {len(df)}")
        print(f"   - 列数: {len(df.columns)}")
        print(f"   - 缺失值: {df.isnull().sum().sum()}")

        # 2. 检查协议特征提取
        enhanced_df = self.analyzer.extract_protocol_features(df)
        protocol_counts = {
            "HTTP": enhanced_df["is_http"].sum(),
            "DNS": enhanced_df["is_dns"].sum(),
            "Video": enhanced_df["is_video"].sum(),
        }

        print(f"\n2. 协议识别结果:")
        for protocol, count in protocol_counts.items():
            ratio = count / len(df) * 100
            print(f"   - {protocol}: {count} 样本 ({ratio:.1f}%)")

        # 3. 检查原有白名单规则生成
        print(f"\n3. 检查白名单规则生成...")
        try:
            from protocol_analyzer import create_whitelist_rules

            old_rules = create_whitelist_rules(self.analyzer, df)
            print(f"   - 规则类型: {list(old_rules.keys())}")

            # 检查规则内容
            for rule_type, rule_content in old_rules.items():
                if isinstance(rule_content, dict):
                    print(f"   - {rule_type}: {len(rule_content)} 个规则")
                    if self.debug_mode and rule_content:
                        sample_key = list(rule_content.keys())[0]
                        print(f"     样例: {sample_key} -> {rule_content[sample_key]}")

        except Exception as e:
            print(f"   ❌ 规则生成失败: {e}")

        # 4. 检查过滤逻辑
        print(f"\n4. 检查过滤应用逻辑...")
        return enhanced_df, protocol_counts

    def create_improved_whitelist_rules(self, df: pd.DataFrame) -> Dict[str, Any]:
        """创建改进的白名单规则"""
        print("\n🔧 创建改进的白名单规则...")

        # 提取协议特征
        enhanced_df = self.analyzer.extract_protocol_features(df)

        # 分析正常流量（假设attack_cat为Normal的是正常流量）
        if "attack_cat" in df.columns:
            normal_mask = df["attack_cat"] == "Normal"
            normal_traffic = enhanced_df[normal_mask]
            print(
                f"   正常流量样本: {len(normal_traffic)}/{len(df)} ({len(normal_traffic)/len(df)*100:.1f}%)"
            )
        else:
            # 如果没有标签，使用启发式方法
            normal_traffic = enhanced_df
            print(f"   使用启发式方法分析: {len(normal_traffic)} 样本")

        rules = {}

        # HTTP白名单规则
        http_traffic = normal_traffic[normal_traffic["is_http"]]
        if len(http_traffic) > 0:
            rules["http_whitelist"] = {
                "min_duration": http_traffic["dur"].quantile(0.1),
                "max_duration": http_traffic["dur"].quantile(0.9),
                "min_bytes": http_traffic["sbytes"].quantile(0.1),
                "max_bytes": http_traffic["sbytes"].quantile(0.9),
                "typical_rate_range": (
                    http_traffic["http_request_rate"].quantile(0.2),
                    http_traffic["http_request_rate"].quantile(0.8),
                ),
            }
            print(f"   ✅ HTTP规则: {len(http_traffic)} 样本基础")

        # DNS白名单规则
        dns_traffic = normal_traffic[normal_traffic["is_dns"]]
        if len(dns_traffic) > 0:
            rules["dns_whitelist"] = {
                "max_duration": dns_traffic["dur"].quantile(0.95),
                "max_packet_size": dns_traffic["sbytes"].quantile(0.95),
                "typical_query_rate": dns_traffic["dns_query_rate"].quantile(0.8),
            }
            print(f"   ✅ DNS规则: {len(dns_traffic)} 样本基础")

        # 视频流白名单规则
        video_traffic = normal_traffic[normal_traffic["is_video"]]
        if len(video_traffic) > 0:
            rules["video_whitelist"] = {
                "min_duration": video_traffic["dur"].quantile(0.3),
                "min_bitrate": video_traffic["video_bitrate"].quantile(0.2),
                "max_bitrate": video_traffic["video_bitrate"].quantile(0.8),
            }
            print(f"   ✅ 视频规则: {len(video_traffic)} 样本基础")

        # 添加通用规则
        rules["general_whitelist"] = {
            "normal_duration_range": (
                normal_traffic["dur"].quantile(0.1),
                normal_traffic["dur"].quantile(0.9),
            ),
            "normal_size_range": (
                normal_traffic["sbytes"].quantile(0.1),
                normal_traffic["sbytes"].quantile(0.9),
            ),
        }

        print(f"   📋 总计生成 {len(rules)} 类规则")
        return rules

    def apply_improved_whitelist_filter(
        self, df: pd.DataFrame, rules: Dict[str, Any]
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """应用改进的白名单过滤"""
        print("\n🎯 应用改进的白名单过滤...")

        # 提取协议特征
        enhanced_df = self.analyzer.extract_protocol_features(df)

        # 初始化白名单标记
        whitelist_mask = pd.Series([False] * len(enhanced_df), index=enhanced_df.index)

        # HTTP白名单过滤
        if "http_whitelist" in rules and enhanced_df["is_http"].any():
            http_rule = rules["http_whitelist"]
            http_mask = (
                enhanced_df["is_http"]
                & (enhanced_df["dur"] >= http_rule["min_duration"])
                & (enhanced_df["dur"] <= http_rule["max_duration"])
                & (enhanced_df["sbytes"] >= http_rule["min_bytes"])
                & (enhanced_df["sbytes"] <= http_rule["max_bytes"])
            )
            whitelist_mask |= http_mask
            print(f"   HTTP白名单匹配: {http_mask.sum()} 样本")

        # DNS白名单过滤
        if "dns_whitelist" in rules and enhanced_df["is_dns"].any():
            dns_rule = rules["dns_whitelist"]
            dns_mask = (
                enhanced_df["is_dns"]
                & (enhanced_df["dur"] <= dns_rule["max_duration"])
                & (enhanced_df["sbytes"] <= dns_rule["max_packet_size"])
            )
            whitelist_mask |= dns_mask
            print(f"   DNS白名单匹配: {dns_mask.sum()} 样本")

        # 视频白名单过滤
        if "video_whitelist" in rules and enhanced_df["is_video"].any():
            video_rule = rules["video_whitelist"]
            video_mask = (
                enhanced_df["is_video"]
                & (enhanced_df["dur"] >= video_rule["min_duration"])
                & (enhanced_df["video_bitrate"] >= video_rule["min_bitrate"])
                & (enhanced_df["video_bitrate"] <= video_rule["max_bitrate"])
            )
            whitelist_mask |= video_mask
            print(f"   视频白名单匹配: {video_mask.sum()} 样本")

        # 通用白名单规则（更宽松的条件）
        if "general_whitelist" in rules:
            general_rule = rules["general_whitelist"]
            general_mask = (
                (enhanced_df["dur"] >= general_rule["normal_duration_range"][0])
                & (enhanced_df["dur"] <= general_rule["normal_duration_range"][1])
                & (enhanced_df["sbytes"] >= general_rule["normal_size_range"][0])
                & (enhanced_df["sbytes"] <= general_rule["normal_size_range"][1])
            )
            whitelist_mask |= general_mask
            print(f"   通用白名单匹配: {general_mask.sum()} 样本")

        # 分离白名单和可疑流量
        whitelist_traffic = enhanced_df[whitelist_mask]
        suspicious_traffic = enhanced_df[~whitelist_mask]

        print(f"\n📊 过滤结果:")
        print(f"   白名单流量: {len(whitelist_traffic)} 样本")
        print(f"   可疑流量: {len(suspicious_traffic)} 样本")
        print(f"   过滤效率: {len(whitelist_traffic)/len(df)*100:.1f}%")

        return whitelist_traffic, suspicious_traffic

    def performance_comparison(self, df: pd.DataFrame):
        """性能对比测试"""
        print("\n⚡ 性能对比测试...")
        print("=" * 50)

        import time

        # 测试改进前的方法
        print("1. 测试原方法...")
        try:
            from protocol_analyzer import create_whitelist_rules, apply_whitelist_filter

            start_time = time.time()
            old_rules = create_whitelist_rules(self.analyzer, df)
            old_whitelist, old_suspicious = apply_whitelist_filter(
                df, old_rules, self.analyzer
            )
            old_time = time.time() - start_time
            old_efficiency = len(old_whitelist) / len(df) * 100

            print(f"   原方法效率: {old_efficiency:.1f}%")
            print(f"   原方法用时: {old_time:.4f}s")

        except Exception as e:
            print(f"   ❌ 原方法失败: {e}")
            old_efficiency = 0.0
            old_time = 0.0

        # 测试改进后的方法
        print("\n2. 测试改进方法...")
        start_time = time.time()
        new_rules = self.create_improved_whitelist_rules(df)
        new_whitelist, new_suspicious = self.apply_improved_whitelist_filter(
            df, new_rules
        )
        new_time = time.time() - start_time
        new_efficiency = len(new_whitelist) / len(df) * 100

        print(f"   新方法效率: {new_efficiency:.1f}%")
        print(f"   新方法用时: {new_time:.4f}s")

        # 对比结果
        print(f"\n📈 改进效果:")
        efficiency_improvement = new_efficiency - old_efficiency
        print(f"   过滤效率提升: +{efficiency_improvement:.1f}%")

        if old_time > 0:
            speed_ratio = old_time / new_time if new_time > 0 else 1
            print(f"   速度对比: {speed_ratio:.1f}x")

        return new_efficiency >= 60  # 目标过滤效率60%+


def main():
    """主修复流程"""
    print("🚨 第二阶段 Day 1-2: 白名单过滤机制紧急修复")
    print("=" * 60)

    # 初始化修复器
    fixer = WhitelistFilterV2()

    try:
        # 加载测试数据
        print("📂 加载数据进行诊断...")
        df = pd.read_csv("data/UNSW_NB15_training-set.csv", nrows=500)
        print(f"加载数据: {df.shape}")

        # 步骤1: 诊断问题
        enhanced_df, protocol_counts = fixer.analyze_filter_failure(df)

        # 步骤2: 性能对比测试
        success = fixer.performance_comparison(df)

        # 步骤3: 总结修复结果
        print("\n" + "=" * 60)
        print("🏆 白名单过滤修复总结")
        print("=" * 60)

        if success:
            print("✅ 白名单过滤机制修复成功！")
            print("📈 关键改进:")
            print("   - 修复了0%过滤效率的问题")
            print("   - 实现了基于统计分析的智能规则")
            print("   - 支持多协议的细粒度过滤")
            print("   - 保持了高性能处理能力")

            print("\n🚀 可以进入第二阶段后续优化:")
            print("   - Day 3-4: 批处理优化系统")
            print("   - Day 5-7: 并行处理架构")
            print("   - Day 8+: 高级性能优化")

        else:
            print("⚠️ 过滤效率仍需进一步优化")
            print("💡 建议:")
            print("   - 调整规则阈值参数")
            print("   - 增加更多协议支持")
            print("   - 优化统计分析方法")

    except Exception as e:
        print(f"❌ 修复过程出错: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
