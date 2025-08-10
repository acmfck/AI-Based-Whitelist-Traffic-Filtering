import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import torch
from torch.utils.data import TensorDataset, DataLoader

def load_nsl_kdd(path, batch_size=256, return_raw=False):
    df = pd.read_csv(path, header=None)
    df = df.sample(frac=1).reset_index(drop=True)

    # 特征 + 标签
    X = df.iloc[:, :-1].copy()
    y = df.iloc[:, -1].copy()

    # 标签编码：normal -> 0，攻击 -> 1
    y = y.apply(lambda x: 0 if x == 'normal' else 1)

    # 类别特征编码
    for col in X.select_dtypes(include='object').columns:
        X[col] = LabelEncoder().fit_transform(X[col])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 划分训练集与测试集
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2)

    X_train_tensor = torch.tensor(X_train).float()
    X_test_tensor = torch.tensor(X_test).float()
    y_train_tensor = torch.tensor(y_train.values).long()
    y_test_tensor = torch.tensor(y_test.values).long()

    train_loader = DataLoader(TensorDataset(X_train_tensor, y_train_tensor), batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(TensorDataset(X_test_tensor, y_test_tensor), batch_size=batch_size)

    if return_raw:
        return train_loader, test_loader, X.shape[1], X_train_tensor, y_train_tensor
    return train_loader, test_loader, X.shape[1]
