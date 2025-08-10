import torch
import torch.nn as nn
import torch.nn.functional as F

class CNN1DClassifier(nn.Module):
    def __init__(self, input_dim, num_classes=2):
        super(CNN1DClassifier, self).__init__()
        self.conv1 = nn.Conv1d(1, 32, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(32)
        self.conv2 = nn.Conv1d(32, 64, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(64)
        self.pool = nn.AdaptiveAvgPool1d(1)  # 输出 [B, C, 1]
        self.fc = nn.Linear(64, num_classes)

    def forward(self, x):
        # 输入 [B, input_dim] -> [B, 1, input_dim]
        x = x.unsqueeze(1)
        x = F.relu(self.bn1(self.conv1(x)))   # [B, 32, input_dim]
        x = F.relu(self.bn2(self.conv2(x)))   # [B, 64, input_dim]
        x = self.pool(x).squeeze(-1)          # [B, 64]
        out = self.fc(x)                      # [B, num_classes]
        return out
