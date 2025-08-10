#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速启动AI检测系统
"""

import os
import webbrowser
import time
from datetime import datetime


def start_system():
    """启动AI检测系统"""
    print("🚀 启动AI白名单流量检测系统")
    print("=" * 50)
    print(f"🕐 启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 创建必要目录
    directories = ["uploads", "processed", "templates", "static"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

    print("✅ 目录结构已准备就绪")

    # 启动提示
    print("\n🌐 系统访问地址:")
    print("   主界面: http://localhost:5000/")
    print("   传统界面: http://localhost:5000/legacy")
    print("   API状态: http://localhost:5000/api/status")
    print("\n📊 功能说明:")
    print("   - 支持上传 PCAP、PCAPNG、CSV 格式文件")
    print("   - AI智能流量分析和异常检测")
    print("   - 实时分析进度显示")
    print("   - 交互式图表和可视化")
    print("   - 结构化分析报告")

    print("\n⚠️  使用提示:")
    print("   - 文件大小限制: 100MB")
    print("   - 按 Ctrl+C 停止服务器")
    print("   - 浏览器将自动打开主页面")

    print("\n" + "=" * 50)

    # 等待2秒后打开浏览器
    time.sleep(2)
    try:
        webbrowser.open("http://localhost:5000/")
        print("🌐 浏览器已自动打开")
    except:
        print("⚠️ 无法自动打开浏览器，请手动访问 http://localhost:5000/")

    # 启动Flask应用
    try:
        from start_server import app

        app.run(host="0.0.0.0", port=5000, debug=True)
    except KeyboardInterrupt:
        print("\n\n⏹️ 系统已停止运行")
        print("感谢使用AI白名单流量检测系统！")
    except Exception as e:
        print(f"\n❌ 系统启动失败: {e}")
        print("请检查依赖包是否已正确安装:")
        print("pip install flask pandas numpy matplotlib scikit-learn werkzeug")


if __name__ == "__main__":
    start_system()
