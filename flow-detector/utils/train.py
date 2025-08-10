import torch
import torch.nn as nn
import torch.optim as optim
from model.lstm_detector import LSTMDetector
from visualization import plot_loss_curve
from data.unsw_nb15_preprocess import load_train_test

# 数据路径
train_csv = r"D:\AI\vscode.ai\flow-detector\data\UNSW_NB15_training-set.csv"
test_csv = r"D:\AI\vscode.ai\flow-detector\data\UNSW_NB15_testing-set.csv"

# 加载数据
train_loader, test_loader, input_dim, scaler = load_train_test(
    train_csv,
    test_csv,
    batch_size=256,
    drop_service=True
)

print(f"训练集大小: {len(train_loader.dataset)}")
print(f"测试集大小: {len(test_loader.dataset)}")

# 模型与训练设置
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = LSTMDetector(input_dim).to(device)
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=1e-3)

loss_list = []
epochs = 10

# 训练循环
for epoch in range(epochs):
    print(f"\nEpoch {epoch + 1}/{epochs}")
    model.train()
    total_loss = 0.0
    for x, y in train_loader:
        x, y = x.to(device), y.to(device)

        if y.dim() > 1:
            y = y.argmax(dim=1)  # 独热标签转为类别
        y = y.long()

        out = model(x)
        loss = criterion(out, y)

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        total_loss += loss.item()

    avg_loss = total_loss / len(train_loader)
    loss_list.append(avg_loss)
    print(f"Train Loss: {avg_loss:.6f}")

# 绘制损失曲线
plot_loss_curve(loss_list)

# 保存模型
# model_path = r"D:\AI\AI-Based-Whitelist-Traffic-Filtering\flow-detector\checkpoint_lstm1.pt"
# torch.save(model.state_dict(), model_path)
# print(f"\n✅ 模型已保存到 {model_path}")
