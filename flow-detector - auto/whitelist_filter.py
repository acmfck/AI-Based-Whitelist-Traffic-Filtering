import torch

def filter_by_whitelist(model, inputs, threshold=0.01):
    """
    使用 AutoEncoder 重建误差过滤白流量
    """
    model.eval()
    with torch.no_grad():
        reconstructed = model(inputs)
        loss = ((inputs - reconstructed) ** 2).mean(dim=1)
        mask = loss > threshold
        return inputs[mask]  # 过滤掉白流量，返回异常候选

