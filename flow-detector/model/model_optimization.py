"""
模型压缩和优化工具
包含量化、剪枝和模型压缩技术
"""

import torch
import torch.nn as nn
import torch.nn.utils.prune as prune
import torch.quantization
import numpy as np
from collections import OrderedDict


class ModelCompressor:
    """模型压缩工具类"""

    @staticmethod
    def quantize_model(model, calibration_loader=None):
        """动态量化模型 (FP32 -> INT8)"""

        # 深拷贝模型
        quantized_model = torch.quantization.quantize_dynamic(
            model.cpu(), {nn.Linear, nn.LSTM, nn.Conv1d}, dtype=torch.qint8
        )

        return quantized_model

    @staticmethod
    def prune_model(model, pruning_rate=0.3):
        """结构化剪枝"""

        pruned_model = model.cpu()

        # 对Linear层进行剪枝
        for name, module in pruned_model.named_modules():
            if isinstance(module, nn.Linear):
                prune.l1_unstructured(module, name="weight", amount=pruning_rate)
                prune.remove(module, "weight")

        return pruned_model

    @staticmethod
    def compress_weights(model, compression_ratio=0.5):
        """权重压缩 - SVD分解"""

        compressed_model = model.cpu()

        for name, module in compressed_model.named_modules():
            if isinstance(module, nn.Linear) and module.weight.size(0) > 32:
                # SVD分解
                weight = module.weight.data
                U, S, V = torch.svd(weight)

                # 保留前k个奇异值
                k = int(min(U.size(1), V.size(0)) * compression_ratio)

                # 重构权重矩阵
                compressed_weight = U[:, :k] @ torch.diag(S[:k]) @ V[:, :k].t()
                module.weight.data = compressed_weight

        return compressed_model


class ModelProfiler:
    """模型性能分析器"""

    @staticmethod
    def profile_model(model, input_tensor, device="cpu"):
        """分析模型性能指标"""

        model = model.to(device)
        input_tensor = input_tensor.to(device)
        model.eval()

        # 计算参数量
        total_params = sum(p.numel() for p in model.parameters())
        trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

        # 计算模型大小
        model_size = sum(p.numel() * p.element_size() for p in model.parameters()) / (
            1024**2
        )  # MB

        # 推理时间测试
        import time

        torch.cuda.synchronize() if device.startswith("cuda") else None

        # 预热
        with torch.no_grad():
            for _ in range(10):
                _ = model(input_tensor)

        # 测试
        start_time = time.time()
        with torch.no_grad():
            for _ in range(100):
                output = model(input_tensor)

        torch.cuda.synchronize() if device.startswith("cuda") else None
        end_time = time.time()

        avg_inference_time = (end_time - start_time) / 100
        throughput = len(input_tensor) / avg_inference_time

        # FLOPs估算 (简化计算)
        flops = ModelProfiler._estimate_flops(model, input_tensor)

        return {
            "total_params": total_params,
            "trainable_params": trainable_params,
            "model_size_mb": model_size,
            "inference_time_ms": avg_inference_time * 1000,
            "throughput_samples_per_sec": throughput,
            "estimated_flops": flops,
        }

    @staticmethod
    def _estimate_flops(model, input_tensor):
        """简化的FLOPs估算"""

        flops = 0

        def hook_fn(module, input, output):
            nonlocal flops

            if isinstance(module, nn.Linear):
                # Linear层: input_size * output_size * batch_size
                flops += module.in_features * module.out_features * input[0].size(0)

            elif isinstance(module, nn.Conv1d):
                # Conv1D层: kernel_size * in_channels * out_channels * output_length * batch_size
                kernel_size = module.kernel_size[0]
                in_channels = module.in_channels
                out_channels = module.out_channels
                output_length = output.size(-1)
                batch_size = output.size(0)
                flops += (
                    kernel_size
                    * in_channels
                    * out_channels
                    * output_length
                    * batch_size
                )

        # 注册hook
        hooks = []
        for module in model.modules():
            if isinstance(module, (nn.Linear, nn.Conv1d)):
                hooks.append(module.register_forward_hook(hook_fn))

        # 前向传播
        with torch.no_grad():
            _ = model(input_tensor)

        # 移除hook
        for hook in hooks:
            hook.remove()

        return flops


def comprehensive_model_optimization(original_model, train_loader, device="cpu"):
    """综合模型优化流程"""

    print("=== 开始综合模型优化 ===")

    # 创建测试输入
    test_input = torch.randn(256, original_model.lstm.input_size).to(device)

    # 1. 原始模型性能
    print("\n1. 原始LSTM模型性能:")
    original_stats = ModelProfiler.profile_model(original_model, test_input, device)
    for key, value in original_stats.items():
        print(f"   {key}: {value}")

    # 2. 动态量化
    print("\n2. 应用动态量化...")
    quantized_model = ModelCompressor.quantize_model(original_model)
    quantized_stats = ModelProfiler.profile_model(
        quantized_model, test_input.cpu(), "cpu"
    )
    print("   量化模型性能:")
    for key, value in quantized_stats.items():
        print(f"   {key}: {value}")

    # 3. 结构化剪枝
    print("\n3. 应用结构化剪枝...")
    pruned_model = ModelCompressor.prune_model(original_model.cpu(), pruning_rate=0.3)
    pruned_stats = ModelProfiler.profile_model(pruned_model, test_input.cpu(), "cpu")
    print("   剪枝模型性能:")
    for key, value in pruned_stats.items():
        print(f"   {key}: {value}")

    # 4. 权重压缩
    print("\n4. 应用权重压缩...")
    compressed_model = ModelCompressor.compress_weights(
        original_model.cpu(), compression_ratio=0.6
    )
    compressed_stats = ModelProfiler.profile_model(
        compressed_model, test_input.cpu(), "cpu"
    )
    print("   压缩模型性能:")
    for key, value in compressed_stats.items():
        print(f"   {key}: {value}")

    # 5. 性能对比表
    print("\n=== 优化效果对比 ===")
    print(
        f"{'方法':<15} {'参数量':<12} {'模型大小(MB)':<15} {'推理时间(ms)':<15} {'吞吐量(samples/s)':<20}"
    )
    print("-" * 85)

    methods = [
        ("原始模型", original_stats),
        ("量化模型", quantized_stats),
        ("剪枝模型", pruned_stats),
        ("压缩模型", compressed_stats),
    ]

    for method_name, stats in methods:
        print(
            f"{method_name:<15} {stats['total_params']:<12,} "
            f"{stats['model_size_mb']:<15.2f} {stats['inference_time_ms']:<15.2f} "
            f"{stats['throughput_samples_per_sec']:<20.0f}"
        )

    return {
        "quantized": quantized_model,
        "pruned": pruned_model,
        "compressed": compressed_model,
        "stats": {
            "original": original_stats,
            "quantized": quantized_stats,
            "pruned": pruned_stats,
            "compressed": compressed_stats,
        },
    }


def save_optimized_models(models_dict, save_dir="optimized_models"):
    """保存优化后的模型"""

    import os

    os.makedirs(save_dir, exist_ok=True)

    for model_name, model in models_dict.items():
        if model_name != "stats":
            save_path = os.path.join(save_dir, f"{model_name}_model.pt")
            torch.save(model.state_dict(), save_path)
            print(f"{model_name} 模型已保存到: {save_path}")


if __name__ == "__main__":
    print("模型压缩和优化工具已准备就绪!")
    print("使用 comprehensive_model_optimization() 函数进行完整优化流程")
