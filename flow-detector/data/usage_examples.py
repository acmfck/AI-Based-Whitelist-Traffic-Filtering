#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
使用示例 - 展示如何传入文件路径使用数据预处理模块
"""

import os
from unsw_nb15_preprocess import (
    AdvancedPcapProcessor,
    PcapToCSVConverter,
    load_file,
    load_train_test,
    preprocess_df,
)


def example_1_process_pcap_file():
    """示例1: 处理PCAP文件 - 传入PCAP文件路径"""
    print("=" * 50)
    print("📦 示例1: 处理PCAP文件")
    print("=" * 50)

    # 在这里传入您的PCAP文件路径
    pcap_file_path = "path/to/your/traffic.pcap"  # 👈 在这里传入PCAP路径

    print(f"📂 处理文件: {pcap_file_path}")

    # 方法1: 使用高级处理器
    processor = AdvancedPcapProcessor()
    try:
        df = processor.read_pcap_advanced(pcap_file_path)  # 不限制包数量
        print(f"✅ 成功处理: {len(df)} 个网络流")
        print(f"📊 特征维度: {df.shape[1]} 列")
        print(f"🔍 前5行预览:")
        print(df.head())
    except FileNotFoundError:
        print(f"❌ 文件不存在: {pcap_file_path}")
        print("💡 请将实际的PCAP文件路径替换到 pcap_file_path 变量中")
    except ImportError as e:
        print(f"❌ 缺少依赖: {e}")
        print("💡 请安装scapy: pip install scapy")
    except Exception as e:
        print(f"❌ 处理失败: {e}")


def example_2_batch_convert_pcap_to_csv():
    """示例2: 批量转换PCAP到CSV - 传入多个PCAP文件路径"""
    print("\n" + "=" * 50)
    print("🔄 示例2: 批量转换PCAP到CSV")
    print("=" * 50)

    # 在这里传入您的PCAP文件路径列表
    pcap_files = [  # 👈 在这里传入PCAP路径列表
        "path/to/traffic1.pcap",
        "path/to/traffic2.pcap",
        "path/to/traffic3.pcap",
    ]

    # 设置输出目录
    output_dir = "converted_data"  # 👈 在这里设置输出目录

    print(f"📂 待处理文件: {len(pcap_files)} 个")
    for i, file_path in enumerate(pcap_files, 1):
        print(f"   {i}. {file_path}")

    print(f"📁 输出目录: {output_dir}")

    try:
        converter = PcapToCSVConverter(output_dir=output_dir)

        # 检查文件是否存在
        existing_files = [f for f in pcap_files if os.path.exists(f)]

        if existing_files:
            csv_file = converter.convert_batch(
                existing_files,
                output_filename="batch_converted_traffic.csv",  # 👈 输出CSV文件名
            )
            print(f"✅ 转换完成: {csv_file}")

            # 获取转换摘要
            summary = converter.get_conversion_summary(csv_file)
            print(f"📊 转换摘要:")
            print(f"   总流量数: {summary['total_flows']}")
            print(f"   协议分布: {summary['protocol_distribution']}")
        else:
            print("❌ 没有找到任何PCAP文件")
            print("💡 请将实际的PCAP文件路径替换到 pcap_files 列表中")

    except Exception as e:
        print(f"❌ 转换失败: {e}")


def example_3_load_csv_data():
    """示例3: 加载CSV数据文件 - 传入CSV文件路径"""
    print("\n" + "=" * 50)
    print("📊 示例3: 加载CSV数据文件")
    print("=" * 50)

    # 在这里传入您的CSV文件路径
    csv_file_path = "UNSW_NB15_training-set.csv"  # 👈 在这里传入CSV路径

    print(f"📂 加载文件: {csv_file_path}")

    try:
        df = load_file(csv_file_path)
        print(f"✅ 成功加载: {len(df)} 行数据")
        print(f"📊 数据维度: {df.shape}")
        print(f"🏷️ 列名: {list(df.columns)[:10]}...")  # 显示前10列

        # 预处理数据
        X, y = preprocess_df(df, drop_service=True)
        print(f"🔧 预处理后: 特征{X.shape}, 标签{y.shape}")

    except FileNotFoundError:
        print(f"❌ 文件不存在: {csv_file_path}")
        print("💡 请确保CSV文件存在于当前目录或提供完整路径")
    except Exception as e:
        print(f"❌ 加载失败: {e}")


def example_4_train_test_loading():
    """示例4: 加载训练测试数据 - 传入训练和测试文件路径"""
    print("\n" + "=" * 50)
    print("🎯 示例4: 加载训练测试数据")
    print("=" * 50)

    # 在这里传入您的训练和测试文件路径
    train_file_path = "UNSW_NB15_training-set.csv"  # 👈 在这里传入训练集路径
    test_file_path = "UNSW_NB15_testing-set.csv"  # 👈 在这里传入测试集路径

    print(f"📚 训练文件: {train_file_path}")
    print(f"🧪 测试文件: {test_file_path}")

    try:
        # 加载数据并创建DataLoader
        train_loader, test_loader, input_dim, scaler = load_train_test(
            train_path=train_file_path,  # 👈 训练文件路径
            test_path=test_file_path,  # 👈 测试文件路径
            batch_size=128,  # 👈 批次大小
            drop_service=True,  # 👈 是否删除service列
        )

        print(f"✅ 加载成功!")
        print(f"🔢 输入特征维度: {input_dim}")
        print(f"📦 训练批次数: {len(train_loader)}")
        print(f"📦 测试批次数: {len(test_loader)}")
        print(f"⚙️ 标准化器: {type(scaler).__name__}")

        # 获取一个批次的数据示例
        for batch_X, batch_y in train_loader:
            print(f"📊 批次数据形状: X={batch_X.shape}, y={batch_y.shape}")
            break

    except FileNotFoundError as e:
        print(f"❌ 文件不存在: {e}")
        print("💡 请确保训练和测试文件存在")
    except Exception as e:
        print(f"❌ 加载失败: {e}")


def example_5_custom_file_paths():
    """示例5: 自定义文件路径配置"""
    print("\n" + "=" * 50)
    print("⚙️ 示例5: 自定义文件路径配置")
    print("=" * 50)

    # 配置文件路径字典
    file_paths = {
        # PCAP文件路径
        "pcap_files": [
            r"D:\data\network_traffic\sample1.pcap",  # 👈 Windows绝对路径
            r"D:\data\network_traffic\sample2.pcap",
            "./data/local_traffic.pcap",  # 👈 相对路径
        ],
        # CSV数据文件路径
        "training_data": r"D:\datasets\UNSW_NB15_training-set.csv",  # 👈 训练数据路径
        "testing_data": r"D:\datasets\UNSW_NB15_testing-set.csv",  # 👈 测试数据路径
        # 输出目录
        "output_dir": r"D:\output\processed_traffic",  # 👈 输出目录路径
        "model_save_dir": r"D:\models\traffic_classifier",  # 👈 模型保存路径
    }

    print("📁 配置的文件路径:")
    for key, value in file_paths.items():
        print(f"   {key}: {value}")

    print("\n💡 路径格式说明:")
    print("• Windows绝对路径: D:\\data\\file.csv")
    print("• Linux/Mac绝对路径: /home/user/data/file.csv")
    print("• 相对路径: ./data/file.csv 或 ../data/file.csv")
    print("• 原始字符串: r'D:\\data\\file.csv' (推荐)")

    print("\n🔧 在代码中使用:")
    print("```python")
    print("# 方法1: 直接传入路径")
    print("df = load_file('path/to/your/file.csv')")
    print("")
    print("# 方法2: 使用配置字典")
    print("train_loader, test_loader, input_dim, scaler = load_train_test(")
    print("    train_path=file_paths['training_data'],")
    print("    test_path=file_paths['testing_data']")
    print(")")
    print("```")


def main():
    """主函数 - 运行所有示例"""
    print("🔧 AI白名单流量过滤系统 - 文件路径传入示例")
    print("=" * 60)

    # 运行所有示例
    example_1_process_pcap_file()
    example_2_batch_convert_pcap_to_csv()
    example_3_load_csv_data()
    example_4_train_test_loading()
    example_5_custom_file_paths()

    print("\n" + "=" * 60)
    print("🎯 总结: 文件路径传入位置")
    print("=" * 60)
    print("1. 📦 PCAP处理: processor.read_pcap_advanced('file.pcap')")
    print("2. 🔄 批量转换: converter.convert_batch(['file1.pcap', 'file2.pcap'])")
    print("3. 📊 CSV加载: load_file('data.csv')")
    print("4. 🎯 训练测试: load_train_test('train.csv', 'test.csv')")
    print("5. ⚙️ 自定义配置: 在变量中定义路径，然后传入函数")

    print("\n💡 重要提示:")
    print("• 使用原始字符串 r'path' 避免转义问题")
    print("• 检查文件是否存在: os.path.exists(file_path)")
    print("• 使用绝对路径避免路径错误")
    print("• 支持的格式: .pcap, .csv, .json, .parquet, .txt")


if __name__ == "__main__":
    main()
