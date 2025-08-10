import torch
import torch.nn as nn
import numpy as np
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    f1_score,
    roc_auc_score,
    roc_curve,
    confusion_matrix,
)
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import seaborn as sns
from data.unsw_nb15_preprocess import load_train_test
from model.lstm_detector import LSTMDetector

# ===== 配置区域 =====
# 使用相对路径
train_csv = "D:/AI/AI-Based-Whitelist-Traffic-Filtering/flow-detector/data/UNSW_NB15_training-set.csv"
test_csv = "D:/AI/AI-Based-Whitelist-Traffic-Filtering/flow-detector/data/UNSW_NB15_testing-set.csv"
model_path = "D:/AI/AI-Based-Whitelist-Traffic-Filtering/flow-detector/checkpoint_lstm1.pt"

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ===== 数据加载 =====
train_loader, test_loader, input_dim, scaler = load_train_test(
    train_csv, test_csv, batch_size=256, drop_service=True
)

# ===== 模型加载 =====
model = LSTMDetector(input_dim).to(device)
model.load_state_dict(torch.load(model_path, map_location=device))
model.eval()

# ===== 模型评估 =====
y_true, y_pred, y_score = [], [], []
X_test = []  # 用于存储测试数据

with torch.no_grad():
    for x, y in test_loader:
        x, y = x.to(device), y.to(device)
        if y.dim() > 1:
            y = y.argmax(dim=1)
        out = model(x)
        pred = out.argmax(dim=1)
        prob = torch.softmax(out, dim=1)[:, 1]  # 正类概率

        y_true.extend(y.cpu().numpy())
        y_pred.extend(pred.cpu().numpy())
        y_score.extend(prob.cpu().numpy())
        X_test.extend(x.cpu().numpy())  # 保存原始测试数据

# ===== 输出结果 =====
print("=== LSTM 模型评估结果 ===")
print(classification_report(y_true, y_pred, digits=4))
print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
print(f"F1 Score: {f1_score(y_true, y_pred):.4f}")
print(f"AUC: {roc_auc_score(y_true, y_score):.4f}")

# === 1. ROC 曲线 ===
fpr, tpr, _ = roc_curve(y_true, y_score)
auc_score = roc_auc_score(y_true, y_score)
plt.figure()
plt.plot(fpr, tpr, label=f"ROC Curve (AUC = {auc_score:.4f})")
plt.plot([0, 1], [0, 1], linestyle="--", color="gray")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# === 2. 混淆矩阵 ===
cm = confusion_matrix(y_true, y_pred)
plt.figure()
sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=["Normal", "Attack"],
    yticklabels=["Normal", "Attack"],
)
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.title("Confusion Matrix")
plt.tight_layout()
plt.show()

# === 3. 编码特征降维可视化 ===
X_test = np.array(X_test)
y_true_np = np.array(y_true)  # 转换为numpy数组

print(f"X_test shape: {X_test.shape}")
print(f"y_true_np shape: {y_true_np.shape}")
print(f"Normal samples: {np.sum(y_true_np == 0)}")
print(f"Attack samples: {np.sum(y_true_np == 1)}")

pca = PCA(n_components=2)
X_vis = pca.fit_transform(X_test)

print(f"PCA explained variance ratio: {pca.explained_variance_ratio_}")

plt.figure(figsize=(10, 8))
plt.scatter(
    X_vis[y_true_np == 0, 0],
    X_vis[y_true_np == 0, 1],
    c="green",
    label="Normal",
    alpha=0.5,
)
plt.scatter(
    X_vis[y_true_np == 1, 0],
    X_vis[y_true_np == 1, 1],
    c="red",
    label="Attack",
    alpha=0.5,
)
plt.title("Encoded Feature Visualization (PCA)")
plt.legend()
plt.xlabel("PCA-1")
plt.ylabel("PCA-2")
plt.grid(True)
plt.tight_layout()
plt.show()
