import torch
import torch.nn as nn

class TransformerClassifier(nn.Module):
    def __init__(self, input_dim, num_classes=2, d_model=128, nhead=4, num_layers=2, dropout=0.1):
        super(TransformerClassifier, self).__init__()
        self.input_proj = nn.Linear(input_dim, d_model)
        encoder_layer = nn.TransformerEncoderLayer(d_model=d_model, nhead=nhead, dropout=dropout, batch_first=True)
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.cls_token = nn.Parameter(torch.randn(1, 1, d_model))  # 类别 token
        self.fc = nn.Linear(d_model, num_classes)

    def forward(self, x):
        # x: [B, input_dim]
        B = x.size(0)
        x = self.input_proj(x).unsqueeze(1)  # [B, 1, d_model]
        cls_tokens = self.cls_token.expand(B, -1, -1)  # [B, 1, d_model]
        x = torch.cat((cls_tokens, x), dim=1)  # [B, 2, d_model]
        out = self.encoder(x)  # [B, 2, d_model]
        cls_output = out[:, 0]  # [B, d_model]
        return self.fc(cls_output)  # [B, num_classes]
