import matplotlib.pyplot as plt

def plot_loss_curve(loss_list):
    plt.plot(loss_list, label='Train Loss')
    plt.xlabel("Epoch")
    plt.ylabel("Loss")
    plt.title("Training Loss Curve")
    plt.legend()    
    plt.grid(True)
    plt.tight_layout() 
    plt.show()
    plt.savefig("flow-detector/loss_curve.png")

