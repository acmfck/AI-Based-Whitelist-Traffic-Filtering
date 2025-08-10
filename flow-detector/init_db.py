#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库初始化脚本
"""

import sqlite3
import os

DATABASE_PATH = "analysis_history.db"


def init_database():
    """初始化数据库"""
    print(f"📊 初始化数据库: {DATABASE_PATH}")

    # 如果数据库文件存在，先备份
    if os.path.exists(DATABASE_PATH):
        backup_path = f"{DATABASE_PATH}.backup"
        print(f"🔄 备份现有数据库到: {backup_path}")
        import shutil

        shutil.copy2(DATABASE_PATH, backup_path)

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # 删除现有表（如果存在）
    cursor.execute("DROP TABLE IF EXISTS analysis_history")
    print("🗑️ 删除旧表")

    # 创建分析历史记录表
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER,
            upload_time TIMESTAMP,
            analysis_time TIMESTAMP,
            processing_time REAL,
            total_flows INTEGER,
            anomaly_count INTEGER,
            security_level TEXT,
            cpu_usage REAL,
            memory_usage REAL,
            analysis_results TEXT,  -- JSON格式存储完整分析结果
            status TEXT DEFAULT 'pending'  -- pending, completed, failed
        )
    """
    )
    print("📋 创建analysis_history表")

    # 创建快速查询索引
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_upload_time ON analysis_history(upload_time)"
    )
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON analysis_history(status)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_filename ON analysis_history(filename)"
    )
    print("🔍 创建索引")

    # 提交更改并关闭连接
    conn.commit()
    conn.close()

    print("✅ 数据库初始化完成")

    # 验证表结构
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print(f"📊 数据库中的表: {tables}")

    cursor.execute("PRAGMA table_info(analysis_history);")
    columns = cursor.fetchall()
    print("📋 analysis_history表结构:")
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")

    conn.close()


if __name__ == "__main__":
    init_database()
