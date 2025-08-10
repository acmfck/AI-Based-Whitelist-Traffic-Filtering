#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI白名单流量检测系统启动器
适用于真实数据检测和分析
"""

import os
import sys
import subprocess
import webbrowser
from pathlib import Path


def check_dependencies():
    """检查系统依赖"""
    print("🔍 检查系统依赖...")

    required_packages = [
        "flask",
        "pandas",
        "numpy",
        "matplotlib",
        "scikit-learn",
        "werkzeug",
    ]

    missing_packages = []

    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
            print(f"✅ {package} 已安装")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} 未安装")

    if missing_packages:
        print(f"\n⚠️ 缺少以下依赖包: {', '.join(missing_packages)}")
        print("请运行以下命令安装:")
        print(f"pip install {' '.join(missing_packages)}")
        return False

    return True


def setup_directories():
    """设置必要的目录结构"""
    print("📁 创建必要目录...")

    directories = [
        "uploads",
        "processed",
        "analysis_results",
        "templates",
        "static",
        "static/css",
        "static/js",
        "static/images",
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ 目录已创建: {directory}")


def check_ai_modules():
    """检查AI检测模块是否可用"""
    print("🤖 检查AI检测模块...")

    ai_modules = ["complete_ai_detection.py", "real_data_visualization.py"]

    available_modules = []

    for module_file in ai_modules:
        if os.path.exists(module_file):
            print(f"✅ AI模块可用: {module_file}")
            available_modules.append(module_file)
        else:
            print(f"⚠️ AI模块不存在: {module_file}")

    if available_modules:
        print(f"🎯 系统将使用真实AI检测功能")
        return True
    else:
        print(f"⚠️ 未找到AI模块，系统将使用模拟模式")
        return False


def start_server(port=5000):
    """启动Flask服务器"""
    print(f"🚀 启动AI白名单流量检测系统...")
    print("=" * 60)
    print(f"🌐 访问地址: http://localhost:{port}")
    print(f"📊 主界面: http://localhost:{port}/")
    print(f"🔧 传统界面: http://localhost:{port}/legacy")
    print("=" * 60)

    # 尝试自动打开浏览器
    try:
        webbrowser.open(f"http://localhost:{port}/")
        print("🌐 浏览器已自动打开")
    except:
        print("⚠️ 无法自动打开浏览器，请手动访问上述地址")

    # 启动Flask应用
    try:
        import start_server

        start_server.app.run(
            host="0.0.0.0", port=port, debug=True, use_reloader=False  # 避免重复启动
        )
    except KeyboardInterrupt:
        print("\n⏹️ 服务器已停止")
    except Exception as e:
        print(f"❌ 启动失败: {e}")
        return False

    return True


def main():
    """主函数"""
    print("🔧 AI白名单流量检测系统启动器")
    print("=" * 60)

    # 1. 检查依赖
    if not check_dependencies():
        print("\n❌ 依赖检查失败，请先安装所需的Python包")
        input("按回车键退出...")
        return

    # 2. 创建目录
    setup_directories()

    # 3. 检查AI模块
    ai_available = check_ai_modules()

    # 4. 启动服务器
    print(f"\n🎯 系统模式: {'真实AI检测' if ai_available else '模拟检测'}")
    print("按 Ctrl+C 停止服务器")
    print("=" * 60)

    try:
        start_server()
    except Exception as e:
        print(f"❌ 系统启动失败: {e}")
        input("按回车键退出...")


if __name__ == "__main__":
    main()
