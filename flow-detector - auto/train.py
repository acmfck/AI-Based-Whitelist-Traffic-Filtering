import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from model.autoencoder import AutoEncoder
from data.unsw_nb15_preprocess import load_train_test
import joblib
import os
from visualization import plot_loss_curve  
import numpy as np

# ===== 配置 =====
train_csv = r"D:\AI\vscode.ai\flow-detector\data\UNSW_NB15_training-set.csv"
test_csv = r"D:\AI\vscode.ai\flow-detector\data\UNSW_NB15_testing-set.csv"
ae_ckpt = r"D:\AI\vscode.ai\flow-detector\checkpoint_autoencoder.pt"
lr_ckpt = r"D:\AI\vscode.ai\flow-detector\logistic_model.pkl"
batch_size = 512
epochs = 10
# =================

# 加载数据
train_loader, _, input_dim, scaler = load_train_test(
    train_csv, test_csv, batch_size=batch_size
)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 训练 AutoEncoder 仅使用正常流量
model = AutoEncoder(input_dim).to(device)
optimizer = optim.Adam(model.parameters(), lr=1e-3)
criterion = nn.MSELoss()

model.train()
loss_list = []
for epoch in range(epochs):
    total_loss = 0
    for x, y in train_loader:
        mask = y == 0
        if mask.sum() == 0:
            continue
        x = x[mask].to(device)

        recon = model(x)
        loss = criterion(recon, x)

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    
    avg_loss = total_loss / len(train_loader)
    loss_list.append(avg_loss)
    print(f"[Epoch {epoch+1}] Loss: {avg_loss:.6f}")

# 绘制损失曲线
plot_loss_curve(loss_list)

# 保存 AutoEncoder 模型
torch.save(model.state_dict(), ae_ckpt)


# 重新加载全量训练集用于LR
import pandas as pd
from data.unsw_nb15_preprocess import preprocess_df

train_df = pd.read_csv(train_csv)
X_all, y_all = preprocess_df(train_df)
X_all_scaled = scaler.transform(X_all)
model.eval()
with torch.no_grad():
    X_encoded = (
        model.encode(torch.tensor(X_all_scaled, dtype=torch.float32).to(device))
        .cpu()
        .numpy()
    )
y_all = y_all.values

# 训练 LR
X_train, X_val, y_train, y_val = train_test_split(
    X_encoded, y_all, test_size=0.2, random_state=42
)
lr = LogisticRegression(max_iter=1000)
lr.fit(X_train, y_train)

# 保存模型
joblib.dump(lr, lr_ckpt)
print("AutoEncoder + Logistic Regression 训练完毕！")
