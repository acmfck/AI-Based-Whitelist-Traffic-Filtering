import pandas as pd
import os

train_path = r"D:\AI\vscode.ai\UNSW_NB15_training-set.csv"
test_path = r"D:\AI\vscode.ai\UNSW_NB15_testing-set.csv"
output_path = r"D:\AI\vscode.ai\UNSW_NB15_training-set.csv"

# 读取训练集和测试集
df_train = pd.read_csv(train_path)
df_test = pd.read_csv(test_path)

# 合并
df_all = pd.concat([df_train, df_test], ignore_index=True)

# 保存为新的训练集
df_all.to_csv(output_path, index=False)
print(f"合并完成，已保存到: {output_path}")
