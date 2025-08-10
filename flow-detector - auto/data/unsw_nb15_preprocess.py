import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
import torch
from torch.utils.data import DataLoader, TensorDataset

def preprocess_df(df, drop_service=True):
    df = df.copy()
    df = df.sample(frac=1).reset_index(drop=True)  # 打乱样本顺序

    # 添加二分类标签（正常 vs 攻击）
    df["label"] = df["attack_cat"].apply(lambda x: 0 if str(x).lower() == "normal" else 1)

    # 需要剔除的字段
    drop_cols = ["id", "attack_cat", "label"]
    if drop_service:
        drop_cols.append("service")

    # 构造特征和标签
    X = df.drop(columns=drop_cols)
    y = df["label"]

    # 编码类别特征
    for col in X.select_dtypes(include="object").columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))

    return X, y


def load_train_test(train_csv, test_csv, batch_size=256, drop_service=True):
    # 加载并处理训练集
    train_df = pd.read_csv(train_csv)
    X_train, y_train = preprocess_df(train_df, drop_service=drop_service)
    # 筛选正常样本（label=0）
    mask = y_train == 0
    X_train = X_train[mask]
    y_train = y_train[mask]

    # 标准化器只对数值列起作用
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # 加载并处理测试集
    test_df = pd.read_csv(test_csv)
    X_test, y_test = preprocess_df(test_df, drop_service=drop_service)

    # 确保训练和测试有相同的列顺序
    X_test = X_test[X_train.columns]
    X_test_scaled = scaler.transform(X_test)

    # 转换为 TensorDataset
    train_dataset = TensorDataset(
        torch.tensor(X_train_scaled, dtype=torch.float32),
        torch.tensor(y_train.values, dtype=torch.long)
    )
    test_dataset = TensorDataset(
        torch.tensor(X_test_scaled, dtype=torch.float32),
        torch.tensor(y_test.values, dtype=torch.long)
    )

    # 封装 DataLoader
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    # 返回数据加载器、特征数、标准化器
    return train_loader, test_loader, X_train.shape[1], scaler
