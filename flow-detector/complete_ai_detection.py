#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整AI检测模块 - 集成LSTM模型检测、流量分析和性能评估
提供complete_ai_detection的核心功能
"""

import torch
import torch.nn as nn
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import time
import os
import json
from typing import Dict, List, Tuple, Any
import psutil
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    f1_score,
    roc_auc_score,
    roc_curve,
    confusion_matrix,
)
from sklearn.decomposition import PCA

# 导入项目模块
try:
    from model.lstm_detector import LSTMDetector
except ImportError:
    print("⚠️ LSTMDetector模块不可用，将使用简化版本")
    LSTMDetector = None

try:
    from data.unsw_nb15_preprocess import load_data_for_inference
except ImportError:
    print("⚠️ 数据预处理模块不可用")

try:
    from enhanced_traffic_analysis import enhanced_traffic_classification
except ImportError:
    print("⚠️ 增强流量分析模块不可用")

try:
    from ultra_clear_visualization import create_comprehensive_visualizations
except ImportError:
    print("⚠️ 可视化模块不可用")


def calculate_ai_accuracy_metrics(
    df: pd.DataFrame, ai_predictions: np.ndarray
) -> Dict[str, Any]:
    """
    计算AI白名单流量过滤的准确率指标

    Args:
        df: 原始数据DataFrame（包含真实标签）
        ai_predictions: AI模型的预测结果

    Returns:
        包含各种准确率指标的字典
    """
    try:
        # 确保ai_predictions是numpy数组
        if isinstance(ai_predictions, list):
            ai_predictions = np.array(ai_predictions)

        # 检查是否有真实标签
        if "label" not in df.columns:
            return {
                "has_ground_truth": False,
                "message": "数据集无真实标签，无法计算准确率",
                "estimated_accuracy": _estimate_accuracy_by_patterns(
                    df, ai_predictions
                ),
            }

        # 处理真实标签
        true_labels = df["label"].copy()

        # 标准化标签格式
        true_binary = (true_labels == "Normal").astype(int)  # 1为正常流量，0为攻击流量
        pred_binary = (ai_predictions > 0.5).astype(int)  # AI预测：1为正常，0为攻击

        # 计算基本指标
        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            f1_score,
            confusion_matrix,
        )

        accuracy = accuracy_score(true_binary, pred_binary)
        precision = precision_score(true_binary, pred_binary, zero_division=0)
        recall = recall_score(true_binary, pred_binary, zero_division=0)
        f1 = f1_score(true_binary, pred_binary, zero_division=0)

        # 混淆矩阵
        cm = confusion_matrix(true_binary, pred_binary)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        # 计算白名单过滤特定指标
        total_normal = np.sum(true_binary == 1)  # 真实正常流量数
        total_attack = np.sum(true_binary == 0)  # 真实攻击流量数

        # 白名单准确率：正确识别为正常的正常流量 / 总正常流量
        whitelist_accuracy = tp / total_normal if total_normal > 0 else 0

        # 误报率：错误识别为正常的攻击流量 / 总攻击流量
        false_positive_rate = fp / total_attack if total_attack > 0 else 0

        # 漏报率：错误识别为攻击的正常流量 / 总正常流量
        false_negative_rate = fn / total_normal if total_normal > 0 else 0

        return {
            "has_ground_truth": True,
            "overall_accuracy": round(accuracy * 100, 2),
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "whitelist_accuracy": round(whitelist_accuracy * 100, 2),
            "false_positive_rate": round(false_positive_rate * 100, 2),
            "false_negative_rate": round(false_negative_rate * 100, 2),
            "confusion_matrix": {
                "true_negative": int(tn),  # 正确识别的攻击流量
                "false_positive": int(fp),  # 误识别为正常的攻击流量
                "false_negative": int(fn),  # 误识别为攻击的正常流量
                "true_positive": int(tp),  # 正确识别的正常流量
            },
            "total_samples": len(df),
            "normal_samples": int(total_normal),
            "attack_samples": int(total_attack),
        }

    except Exception as e:
        print(f"准确率计算失败: {e}")
        return {
            "has_ground_truth": False,
            "error": str(e),
            "estimated_accuracy": _estimate_accuracy_by_patterns(df, ai_predictions),
        }


def _estimate_accuracy_by_patterns(
    df: pd.DataFrame, ai_predictions: np.ndarray
) -> Dict[str, Any]:
    """
    当没有真实标签时，基于流量模式估算准确率
    """
    try:
        print(
            f"🔍 开始估算准确率，数据长度: {len(df)}, 预测长度: {len(ai_predictions)}"
        )

        # 确保ai_predictions是numpy数组
        if isinstance(ai_predictions, list):
            ai_predictions = np.array(ai_predictions)

        pred_binary = (ai_predictions > 0.5).astype(int)
        normal_ratio = np.mean(pred_binary)
        print(f"🔍 预测的正常流量比例: {normal_ratio}")

        # 基于网络流量的经验规律估算
        expected_normal_ratio = 0.85  # 一般网络中正常流量占85%左右
        confidence = max(0, 100 - abs(normal_ratio - expected_normal_ratio) * 200)
        print(f"🔍 置信度计算: {confidence}")

        result = {
            "estimated_normal_ratio": round(normal_ratio * 100, 2),
            "expected_normal_ratio": round(expected_normal_ratio * 100, 2),
            "confidence_score": round(confidence, 2),
            "message": "基于流量模式的估算准确率",
        }
        print(f"🔍 估算结果: {result}")
        return result
    except Exception as e:
        print(f"❌ 估算准确率失败: {e}")
        return {"confidence_score": 0, "message": "无法估算准确率"}


def _analyze_traffic_size_distribution(df: pd.DataFrame) -> Dict[str, int]:
    """分析流量大小分布"""
    try:
        if "sbytes" not in df.columns:
            return {"无数据": 0}

        sizes = df["sbytes"].fillna(0)

        # 定义大小区间
        bins = [0, 64, 512, 1024, 4096, float("inf")]
        labels = [
            "小包(<64B)",
            "中小包(64-512B)",
            "中包(512B-1KB)",
            "中大包(1-4KB)",
            "大包(>4KB)",
        ]

        # 分类统计
        size_categories = pd.cut(sizes, bins=bins, labels=labels, include_lowest=True)
        distribution = size_categories.value_counts().to_dict()

        # 确保所有类别都存在
        result = {}
        for label in labels:
            result[label] = int(distribution.get(label, 0))

        return result

    except Exception as e:
        print(f"流量大小分析失败: {e}")
        return {"分析失败": 0}


def _analyze_duration_distribution(df: pd.DataFrame) -> Dict[str, int]:
    """分析连接持续时间分布"""
    try:
        if "dur" not in df.columns:
            return {"无数据": 0}

        durations = df["dur"].fillna(0)

        # 定义时间区间（秒）
        bins = [0, 1, 10, 60, 300, float("inf")]
        labels = [
            "瞬时(<1s)",
            "短时(1-10s)",
            "中等(10s-1min)",
            "长时(1-5min)",
            "持久(>5min)",
        ]

        # 分类统计
        duration_categories = pd.cut(
            durations, bins=bins, labels=labels, include_lowest=True
        )
        distribution = duration_categories.value_counts().to_dict()

        # 确保所有类别都存在
        result = {}
        for label in labels:
            result[label] = int(distribution.get(label, 0))

        return result

    except Exception as e:
        print(f"连接时长分析失败: {e}")
        return {"分析失败": 0}


def _analyze_packet_count_distribution(df: pd.DataFrame) -> Dict[str, int]:
    """分析包数量分布"""
    try:
        if "spkts" not in df.columns:
            return {"无数据": 0}

        packet_counts = df["spkts"].fillna(0)

        # 定义包数量区间
        bins = [0, 10, 50, 100, 500, float("inf")]
        labels = [
            "少量(<10包)",
            "中少(10-50包)",
            "中等(50-100包)",
            "较多(100-500包)",
            "大量(>500包)",
        ]

        # 分类统计
        packet_categories = pd.cut(
            packet_counts, bins=bins, labels=labels, include_lowest=True
        )
        distribution = packet_categories.value_counts().to_dict()

        # 确保所有类别都存在
        result = {}
        for label in labels:
            result[label] = int(distribution.get(label, 0))

        return result

    except Exception as e:
        print(f"包数量分析失败: {e}")
        return {"分析失败": 0}


# 简化的LSTM检测器（如果原始模块不可用）
class SimpleLSTMDetector(nn.Module):
    """简化的LSTM检测器"""

    def __init__(self, input_dim, hidden_dim=128, num_layers=2, num_classes=2):
        super(SimpleLSTMDetector, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        self.lstm = nn.LSTM(
            input_dim, hidden_dim, num_layers, batch_first=True, dropout=0.2
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )

    def forward(self, x):
        # 如果输入是2D，扩展为3D
        if len(x.shape) == 2:
            x = x.unsqueeze(1)

        lstm_out, (hidden, _) = self.lstm(x)
        # 使用最后一个时间步的输出
        output = self.classifier(lstm_out[:, -1, :])
        return output


class PerformanceMonitor:
    """性能监控器"""

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.start_memory = None
        self.start_cpu = None

    def start_detection(self):
        """开始性能监控"""
        self.start_time = time.time()
        self.start_memory = psutil.virtual_memory().used / (1024 * 1024)  # MB
        self.start_cpu = psutil.cpu_percent(interval=None)

    def end_detection(self):
        """结束性能监控"""
        self.end_time = time.time()

    def get_stats(self) -> Dict:
        """获取性能统计"""
        if self.start_time is None or self.end_time is None:
            return {}

        processing_time = self.end_time - self.start_time
        end_memory = psutil.virtual_memory().used / (1024 * 1024)
        memory_usage = end_memory - self.start_memory if self.start_memory else 0
        cpu_usage = psutil.cpu_percent(interval=None)

        return {
            "processing_time": round(processing_time, 2),
            "memory_usage_mb": round(memory_usage, 2),
            "cpu_usage_percent": round(cpu_usage, 2),
            "timestamp": datetime.now().isoformat(),
        }


class CompleteAIDetector:
    """完整AI检测器类"""

    def __init__(self, model_path: str = None):
        """初始化AI检测器"""
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        # 使用绝对路径确保能找到模型文件
        current_dir = os.path.dirname(os.path.abspath(__file__))
        default_model_path = os.path.join(current_dir, "checkpoint_lstm1.pt")
        self.model_path = model_path or default_model_path
        self.performance_monitor = PerformanceMonitor()

    def load_model(self, input_dim: int = None):
        """加载LSTM模型"""
        try:
            # 先尝试加载模型文件获取正确的输入维度
            if os.path.exists(self.model_path):
                checkpoint = torch.load(
                    self.model_path, map_location=self.device, weights_only=False
                )

                # 从checkpoint中推断输入维度
                if "lstm.weight_ih_l0" in checkpoint:
                    model_input_dim = checkpoint["lstm.weight_ih_l0"].shape[1]
                    print(f"📏 从模型文件推断输入维度: {model_input_dim}")
                else:
                    model_input_dim = input_dim if input_dim else 42
                    print(f"📏 使用默认输入维度: {model_input_dim}")
            else:
                model_input_dim = input_dim if input_dim else 42
                print(f"📏 模型文件不存在，使用默认维度: {model_input_dim}")

            # 优先使用原始LSTMDetector，如果不可用则使用简化版本
            if LSTMDetector:
                self.model = LSTMDetector(model_input_dim).to(self.device)
            else:
                self.model = SimpleLSTMDetector(model_input_dim).to(self.device)

            if os.path.exists(self.model_path):
                self.model.load_state_dict(
                    torch.load(
                        self.model_path, map_location=self.device, weights_only=False
                    )
                )
                self.model.eval()
                print(f"✅ 模型加载成功: {self.model_path}")
                return True
            else:
                print(f"❌ 模型文件不存在: {self.model_path}")
                return False
        except Exception as e:
            print(f"❌ 模型加载失败: {e}")
            return False

    def preprocess_data(self, csv_path: str) -> Tuple[torch.Tensor, pd.DataFrame, Dict]:
        """预处理CSV数据"""
        try:
            df = pd.read_csv(csv_path)
            print(f"📊 数据加载完成: {len(df)} 行, {len(df.columns)} 列")

            # 基本数据预处理
            df = self._clean_data(df)

            # 特征工程
            features = self._extract_features(df)

            # 转换为tensor
            X = torch.FloatTensor(features).to(self.device)

            basic_info = {
                "total_flows": len(df),
                "features": features.shape[1] if len(features.shape) > 1 else 1,
                "timestamp": datetime.now().isoformat(),
            }

            return X, df, basic_info

        except Exception as e:
            print(f"❌ 数据预处理失败: {e}")
            return None, None, None

    def _clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """清洗数据"""
        # 处理缺失值
        df = df.fillna(0)

        # 处理无限值
        df = df.replace([np.inf, -np.inf], 0)

        # 确保数值类型
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        df[numeric_columns] = df[numeric_columns].astype(float)

        return df

    def _extract_features(self, df: pd.DataFrame) -> np.ndarray:
        """提取特征向量"""
        # 选择数值特征
        feature_columns = [
            "dur",
            "spkts",
            "dpkts",
            "sbytes",
            "dbytes",
            "rate",
            "sttl",
            "dttl",
            "sload",
            "dload",
            "sloss",
            "dloss",
            "sinpkt",
            "dinpkt",
            "sjit",
            "djit",
            "swin",
            "stcpb",
            "dtcpb",
            "dwin",
            "tcprtt",
            "synack",
            "ackdat",
            "smean",
            "dmean",
            "trans_depth",
            "response_body_len",
            "ct_srv_src",
            "ct_state_ttl",
            "ct_dst_ltm",
            "ct_src_dport_ltm",
            "ct_dst_sport_ltm",
            "ct_dst_src_ltm",
            "ct_ftp_cmd",
            "ct_flw_http_mthd",
            "ct_src_ltm",
            "ct_srv_dst",
            "is_ftp_login",
            "is_sm_ips_ports",
        ]

        # 选择存在的特征列
        available_features = [col for col in feature_columns if col in df.columns]

        if not available_features:
            # 如果没有预定义特征，使用所有数值列
            available_features = df.select_dtypes(include=[np.number]).columns.tolist()

        # 提取特征矩阵
        features = df[available_features].values

        # 标准化处理
        features = (features - features.mean(axis=0)) / (features.std(axis=0) + 1e-8)

        return features

    def detect_traffic(self, X: torch.Tensor) -> Dict:
        """执行AI检测"""
        if self.model is None:
            return {"error": "模型未加载"}

        try:
            self.performance_monitor.start_detection()

            with torch.no_grad():
                # 批量预测
                batch_size = 256
                predictions = []
                probabilities = []

                for i in range(0, len(X), batch_size):
                    batch = X[i : i + batch_size]
                    output = self.model(batch)

                    # 获取预测和概率
                    pred = output.argmax(dim=1)
                    prob = torch.softmax(output, dim=1)

                    predictions.extend(pred.cpu().numpy())
                    probabilities.extend(prob.cpu().numpy())

            predictions = np.array(predictions)
            probabilities = np.array(probabilities)

            self.performance_monitor.end_detection()

            # 统计结果
            normal_count = np.sum(predictions == 0)
            attack_count = np.sum(predictions == 1)
            total_count = len(predictions)

            detection_results = {
                "total_flows": total_count,
                "normal_flows": int(normal_count),
                "attack_flows": int(attack_count),
                "normal_percentage": (
                    float(normal_count / total_count * 100) if total_count > 0 else 0
                ),
                "attack_percentage": (
                    float(attack_count / total_count * 100) if total_count > 0 else 0
                ),
                "predictions": predictions.tolist(),
                "probabilities": probabilities.tolist(),
                "confidence_scores": np.max(probabilities, axis=1).tolist(),
            }

            return detection_results

        except Exception as e:
            print(f"❌ AI检测失败: {e}")
            return {"error": str(e)}


def create_visualizations(df: pd.DataFrame, detection_results: Dict, output_dir: str):
    """创建可视化图表"""
    try:
        os.makedirs(output_dir, exist_ok=True)

        # 1. 协议分布图
        plt.figure(figsize=(10, 6))
        if "proto" in df.columns:
            proto_counts = df["proto"].value_counts().head(10)
            plt.subplot(2, 2, 1)
            proto_counts.plot(kind="bar")
            plt.title("Protocol Distribution")
            plt.xticks(rotation=45)

        # 2. 服务分布图
        if "service" in df.columns:
            plt.subplot(2, 2, 2)
            service_counts = df["service"].value_counts().head(10)
            service_counts.plot(kind="bar")
            plt.title("Service Distribution")
            plt.xticks(rotation=45)

        # 3. 检测结果饼图
        plt.subplot(2, 2, 3)
        labels = ["Normal", "Attack"]
        sizes = [
            detection_results.get("normal_flows", 0),
            detection_results.get("attack_flows", 0),
        ]
        colors = ["lightgreen", "lightcoral"]
        plt.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90)
        plt.title("Detection Results")

        # 4. 流量时间序列（如果有时间戳）
        plt.subplot(2, 2, 4)
        if "dur" in df.columns:
            plt.hist(df["dur"], bins=50, alpha=0.7, color="skyblue")
            plt.title("Duration Distribution")
            plt.xlabel("Duration (seconds)")
            plt.ylabel("Frequency")

        plt.tight_layout()
        plot_path = os.path.join(output_dir, "traffic_analysis.png")
        plt.savefig(plot_path, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"✅ 可视化图表已保存: {plot_path}")
        return plot_path

    except Exception as e:
        print(f"❌ 可视化创建失败: {e}")
        return None


def analyze_attack_patterns(df: pd.DataFrame, predictions: List[int]) -> Dict:
    """分析攻击模式"""
    try:
        attack_analysis = {}

        # 创建预测标签
        df_with_pred = df.copy()
        df_with_pred["prediction"] = predictions

        # 攻击流量分析
        attack_flows = df_with_pred[df_with_pred["prediction"] == 1]

        if len(attack_flows) > 0:
            attack_analysis = {
                "attack_count": len(attack_flows),
                "attack_protocols": (
                    attack_flows["proto"].value_counts().to_dict()
                    if "proto" in attack_flows.columns
                    else {}
                ),
                "attack_services": (
                    attack_flows["service"].value_counts().to_dict()
                    if "service" in attack_flows.columns
                    else {}
                ),
                "avg_duration": (
                    float(attack_flows["dur"].mean())
                    if "dur" in attack_flows.columns
                    else 0
                ),
                "avg_bytes": (
                    float(
                        (
                            attack_flows.get("sbytes", 0)
                            + attack_flows.get("dbytes", 0)
                        ).mean()
                    )
                    if "sbytes" in attack_flows.columns
                    else 0
                ),
            }

        return attack_analysis

    except Exception as e:
        print(f"❌ 攻击模式分析失败: {e}")
        return {}


def run_complete_analysis(csv_path: str, output_dir: str = ".") -> Dict:
    """
    运行完整的AI分析流程

    Args:
        csv_path: CSV数据文件路径
        output_dir: 输出目录

    Returns:
        完整的分析结果字典
    """
    try:
        print("🚀 开始完整AI分析流程...")

        # 1. 初始化AI检测器
        detector = CompleteAIDetector()

        # 2. 数据预处理
        print("📊 数据预处理...")
        X, df, basic_info = detector.preprocess_data(csv_path)

        if X is None or df is None:
            return {"error": "数据预处理失败"}

        # 3. 加载模型（先加载以获取正确维度）
        print("🧠 加载AI模型...")
        model_loaded = detector.load_model()

        if not model_loaded:
            return {"error": "模型加载失败"}

        # 4. 根据模型调整数据维度
        expected_dim = None
        if hasattr(detector.model, "lstm"):
            expected_dim = detector.model.lstm.weight_ih_l0.shape[1]
        elif hasattr(detector.model, "classifier"):
            # 对于简化版本，从分类器推断
            pass

        if expected_dim and expected_dim != X.shape[1]:
            print(f"⚙️ 调整特征维度: {X.shape[1]} -> {expected_dim}")
            if X.shape[1] < expected_dim:
                # 如果当前特征少于期望，补零
                padding = torch.zeros(X.shape[0], expected_dim - X.shape[1]).to(
                    X.device
                )
                X = torch.cat([X, padding], dim=1)
            elif X.shape[1] > expected_dim:
                # 如果当前特征多于期望，截取
                X = X[:, :expected_dim]

        # 4. 执行AI检测
        print("🔍 执行AI检测...")
        detection_results = detector.detect_traffic(X)

        if "error" in detection_results:
            return detection_results

        # 6. 计算AI准确率指标
        print("📊 计算AI准确率指标...")
        accuracy_metrics = calculate_ai_accuracy_metrics(
            df, detection_results["predictions"]
        )
        print(f"✅ 准确率分析完成: {accuracy_metrics.get('has_ground_truth', False)}")
        if accuracy_metrics.get("has_ground_truth"):
            print(f"   总体准确率: {accuracy_metrics.get('overall_accuracy', 0)}%")
            print(f"   白名单准确率: {accuracy_metrics.get('whitelist_accuracy', 0)}%")

        # 7. 性能统计
        performance_stats = detector.performance_monitor.get_stats()

        # 8. 攻击模式分析
        print("🎯 分析攻击模式...")
        attack_analysis = analyze_attack_patterns(df, detection_results["predictions"])

        # 9. 增强流量分类（如果模块可用）
        enhanced_classification = {}
        try:
            print("🔍 执行增强流量分类分析...")

            # 调用增强流量分类函数
            if "enhanced_traffic_classification" in globals():
                enhanced_classification = enhanced_traffic_classification(df)
                print("✅ 增强流量分类完成")
            else:
                print("⚠️ 增强流量分类模块不可用")
                enhanced_classification = {"status": "module_unavailable"}
        except Exception as e:
            print(f"⚠️ 增强流量分类失败: {e}")
            enhanced_classification = {"error": str(e)}

        # 8. 创建可视化图表
        print("📈 创建可视化图表...")
        visualization_path = create_visualizations(df, detection_results, output_dir)

        # 9. 协议和服务分析
        protocol_analysis = {}
        service_analysis = {}
        state_analysis = {}

        if "proto" in df.columns:
            protocol_analysis = df["proto"].value_counts().to_dict()

        if "service" in df.columns:
            service_analysis = df["service"].value_counts().to_dict()

        if "state" in df.columns:
            state_analysis = df["state"].value_counts().to_dict()

        # 10. 构建完整结果
        complete_results = {
            "basic_info": {
                **basic_info,
                "processing_time": performance_stats.get("processing_time", 0),
            },
            "detection_results": detection_results,
            "accuracy_metrics": accuracy_metrics,
            "performance_stats": performance_stats,
            "attack_analysis": attack_analysis,
            "protocol_analysis": protocol_analysis,
            "service_analysis": service_analysis,
            "state_analysis": state_analysis,
            "enhanced_classification": enhanced_classification,
            "pattern_analysis": {
                "high_risk_flows": detection_results.get("attack_flows", 0),
                "normal_flows": detection_results.get("normal_flows", 0),
                "confidence_distribution": {
                    "high": len(
                        [
                            c
                            for c in detection_results.get("confidence_scores", [])
                            if c > 0.8
                        ]
                    ),
                    "medium": len(
                        [
                            c
                            for c in detection_results.get("confidence_scores", [])
                            if 0.5 < c <= 0.8
                        ]
                    ),
                    "low": len(
                        [
                            c
                            for c in detection_results.get("confidence_scores", [])
                            if c <= 0.5
                        ]
                    ),
                },
                "size_distribution": _analyze_traffic_size_distribution(df),
                "duration_distribution": _analyze_duration_distribution(df),
                "packet_distribution": _analyze_packet_count_distribution(df),
            },
            "visualization_path": visualization_path,
            "timestamp": datetime.now().isoformat(),
            "status": "success",
        }

        # 11. 保存结果到JSON文件
        result_file = os.path.join(
            output_dir,
            f"ai_analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        try:
            with open(result_file, "w", encoding="utf-8") as f:
                json.dump(
                    complete_results, f, indent=2, ensure_ascii=False, default=str
                )
            print(f"✅ 分析结果已保存: {result_file}")
        except Exception as e:
            print(f"⚠️ 结果保存失败: {e}")

        print("✅ 完整AI分析流程完成！")
        return complete_results

    except Exception as e:
        print(f"❌ 完整AI分析失败: {e}")
        import traceback

        traceback.print_exc()
        return {"error": str(e), "timestamp": datetime.now().isoformat()}


if __name__ == "__main__":
    # 测试函数
    test_csv = "test_data.csv"
    if os.path.exists(test_csv):
        results = run_complete_analysis(test_csv)
        print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
    else:
        print("测试文件不存在，跳过测试")
