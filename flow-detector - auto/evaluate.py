import torch
import joblib
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
from model.autoencoder import AutoEncoder
from data.unsw_nb15_preprocess import load_train_test

# ===== 路径配置 =====
test_csv = r"D:\AI\vscode.ai\flow-detector\data\UNSW_NB15_testing-set.csv"
ae_ckpt = r"D:\AI\vscode.ai\flow-detector\checkpoint_autoencoder.pt"
lr_ckpt = r"D:\AI\vscode.ai\flow-detector\logistic_model.pkl"
# ===================

_, test_loader, input_dim, scaler = load_train_test(
    test_csv, test_csv, batch_size=512, drop_service=True
)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 加载模型
ae = AutoEncoder(input_dim).to(device)
ae.load_state_dict(torch.load(ae_ckpt, map_location=device))
ae.eval()

lr = joblib.load(lr_ckpt)

# 提取测试特征
X_test, y_true = [], []
with torch.no_grad():
    for x, y in test_loader:
        z = ae.encode(x.to(device)).cpu().numpy()
        X_test.append(z)
        y_true.append(y.numpy())

X_test = np.concatenate(X_test, axis=0)
y_true = np.concatenate(y_true, axis=0)

# 预测与评估
y_prob = lr.predict_proba(X_test)[:, 1]
y_pred = (y_prob > 0.5).astype(int)

print("=== 评估结果 ===")
print(classification_report(y_true, y_pred, digits=4))
print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
print(f"F1 Score: {f1_score(y_true, y_pred):.4f}")
print(f"AUC: {roc_auc_score(y_true, y_prob):.4f}")


# === 1. ROC 曲线 ===
fpr, tpr, _ = roc_curve(y_true, y_prob)
plt.figure()
plt.plot(fpr, tpr, label=f"ROC Curve (AUC = {roc_auc_score(y_true, y_prob):.4f})")
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
pca = PCA(n_components=2)
X_vis = pca.fit_transform(X_test)

plt.figure()
plt.scatter(
    X_vis[y_true == 0, 0], X_vis[y_true == 0, 1], c="green", label="Normal", alpha=0.5
)
plt.scatter(
    X_vis[y_true == 1, 0], X_vis[y_true == 1, 1], c="red", label="Attack", alpha=0.5
)
plt.title("Encoded Feature Visualization (PCA)")
plt.legend()
plt.xlabel("PCA-1")
plt.ylabel("PCA-2")
plt.grid(True)
plt.tight_layout()
plt.show()
