"""
轻量级模型实现 - MLP和优化版CNN
替代LSTM以提升推理速度
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class LightweightMLP(nn.Module):
    """轻量级多层感知机 - 替代LSTM"""

    def __init__(self, input_dim, hidden_dims=[64, 32], dropout=0.2):
        super().__init__()

        layers = []
        prev_dim = input_dim

        for hidden_dim in hidden_dims:
            layers.extend(
                [
                    nn.Linear(prev_dim, hidden_dim),
                    nn.BatchNorm1d(hidden_dim),
                    nn.ReLU(),
                    nn.Dropout(dropout),
                ]
            )
            prev_dim = hidden_dim

        # 输出层
        layers.append(nn.Linear(prev_dim, 2))

        self.network = nn.Sequential(*layers)

    def forward(self, x):
        return self.network(x)


class CompactCNN(nn.Module):
    """紧凑型CNN - 针对序列特征优化"""

    def __init__(self, input_dim, num_filters=32, kernel_size=3):
        super().__init__()

        self.input_dim = input_dim

        # 1D卷积层
        self.conv1 = nn.Conv1d(1, num_filters, kernel_size, padding=1)
        self.conv2 = nn.Conv1d(num_filters, num_filters * 2, kernel_size, padding=1)

        # 批归一化
        self.bn1 = nn.BatchNorm1d(num_filters)
        self.bn2 = nn.BatchNorm1d(num_filters * 2)

        # 全局平均池化替代全连接层
        self.global_pool = nn.AdaptiveAvgPool1d(1)

        # 分类层
        self.classifier = nn.Sequential(
            nn.Linear(num_filters * 2, 32), nn.ReLU(), nn.Dropout(0.2), nn.Linear(32, 2)
        )

    def forward(self, x):
        # x: [batch, features] -> [batch, 1, features]
        x = x.unsqueeze(1)

        # 卷积层
        x = F.relu(self.bn1(self.conv1(x)))
        x = F.relu(self.bn2(self.conv2(x)))

        # 全局池化
        x = self.global_pool(x)  # [batch, channels, 1]
        x = x.squeeze(-1)  # [batch, channels]

        # 分类
        return self.classifier(x)


class PrunedMLP(nn.Module):
    """剪枝后的MLP - 稀疏连接"""

    def __init__(self, input_dim, hidden_dims=[64, 32], sparsity=0.3):
        super().__init__()

        self.layers = nn.ModuleList()
        prev_dim = input_dim

        for hidden_dim in hidden_dims:
            layer = nn.Linear(prev_dim, hidden_dim)
            # 应用结构化剪枝
            self._apply_pruning(layer, sparsity)
            self.layers.append(layer)
            prev_dim = hidden_dim

        # 输出层
        self.output_layer = nn.Linear(prev_dim, 2)

    def _apply_pruning(self, layer, sparsity):
        """应用权重剪枝"""
        with torch.no_grad():
            weight = layer.weight
            # 计算权重的阈值
            threshold = torch.quantile(torch.abs(weight), sparsity)
            # 将小于阈值的权重设为0
            mask = torch.abs(weight) >= threshold
            layer.weight.data = weight * mask

    def forward(self, x):
        for layer in self.layers:
            x = F.relu(layer(x))
        return self.output_layer(x)


class DistilledMLP(nn.Module):
    """通过知识蒸馏训练的学生模型"""

    def __init__(self, input_dim, hidden_dim=32):
        super().__init__()

        self.network = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 2),
        )

    def forward(self, x):
        return self.network(x)


def knowledge_distillation_loss(
    student_logits, teacher_logits, true_labels, temperature=3.0, alpha=0.7
):
    """知识蒸馏损失函数"""

    # 软标签损失
    teacher_probs = F.softmax(teacher_logits / temperature, dim=1)
    student_log_probs = F.log_softmax(student_logits / temperature, dim=1)
    soft_loss = F.kl_div(student_log_probs, teacher_probs, reduction="batchmean")
    soft_loss *= temperature**2

    # 硬标签损失
    hard_loss = F.cross_entropy(student_logits, true_labels)

    # 组合损失
    return alpha * soft_loss + (1 - alpha) * hard_loss


def model_comparison_benchmark():
    """模型性能对比基准测试"""

    input_dim = 42  # UNSW-NB15特征维度
    batch_size = 256

    # 创建模型
    models = {
        "LSTM": None,  # 需要从外部加载
        "LightweightMLP": LightweightMLP(input_dim),
        "CompactCNN": CompactCNN(input_dim),
        "PrunedMLP": PrunedMLP(input_dim),
        "DistilledMLP": DistilledMLP(input_dim),
    }

    # 计算模型参数量
    def count_parameters(model):
        return sum(p.numel() for p in model.parameters() if p.requires_grad)

    print("=== 模型参数量对比 ===")
    for name, model in models.items():
        if model is not None:
            params = count_parameters(model)
            print(f"{name}: {params:,} 参数")

    # 推理速度测试
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    test_input = torch.randn(batch_size, input_dim).to(device)

    print("\n=== 推理速度对比 ===")
    import time

    for name, model in models.items():
        if model is not None:
            model = model.to(device)
            model.eval()

            # 预热
            with torch.no_grad():
                for _ in range(10):
                    _ = model(test_input)

            # 测试推理时间
            torch.cuda.synchronize() if torch.cuda.is_available() else None
            start_time = time.time()

            with torch.no_grad():
                for _ in range(100):
                    _ = model(test_input)

            torch.cuda.synchronize() if torch.cuda.is_available() else None
            end_time = time.time()

            avg_time = (end_time - start_time) / 100
            throughput = batch_size / avg_time

            print(f"{name}: {avg_time*1000:.2f}ms/batch, {throughput:.0f} samples/s")


def train_distilled_model(teacher_model, train_loader, device, epochs=10):
    """训练知识蒸馏学生模型"""

    student_model = DistilledMLP(input_dim=teacher_model.lstm.input_size)
    student_model = student_model.to(device)

    optimizer = torch.optim.Adam(student_model.parameters(), lr=0.001)

    teacher_model.eval()
    student_model.train()

    print("开始知识蒸馏训练...")

    for epoch in range(epochs):
        total_loss = 0
        num_batches = 0

        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)

            # 教师模型预测
            with torch.no_grad():
                teacher_logits = teacher_model(batch_x)

            # 学生模型预测
            student_logits = student_model(batch_x)

            # 计算蒸馏损失
            loss = knowledge_distillation_loss(student_logits, teacher_logits, batch_y)

            # 反向传播
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            num_batches += 1

        avg_loss = total_loss / num_batches
        print(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")

    print("知识蒸馏训练完成!")
    return student_model


if __name__ == "__main__":
    print("=== 轻量级模型基准测试 ===")
    model_comparison_benchmark()
