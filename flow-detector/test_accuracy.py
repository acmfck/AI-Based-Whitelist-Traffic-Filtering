#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from complete_ai_detection import run_complete_analysis
import json


def test_accuracy():
    print("🔍 开始测试准确率计算...")
    result = run_complete_analysis(
        r"D:\AI\AI-Based-Whitelist-Traffic-Filtering\flow-detector\test_with_attacks.csv",
        "processed",
    )

    if result:
        print(f"✅ 分析完成，结果键: {list(result.keys())}")

        if "accuracy_metrics" in result:
            accuracy_metrics = result["accuracy_metrics"]
            print("\n📊 准确率计算结果:")
            print(json.dumps(accuracy_metrics, indent=2, ensure_ascii=False))
        else:
            print("❌ 没有找到accuracy_metrics")
    else:
        print("❌ 分析失败")


if __name__ == "__main__":
    test_accuracy()
