import time
import psutil
import matplotlib.pyplot as plt

def simulate_detection(samples, with_filter=False):
    process = psutil.Process()
    start_time = time.time()
    if with_filter:
        time.sleep(0.3)
        effective_samples = int(samples * 0.6)
    else:
        time.sleep(0.6)
        effective_samples = samples
    elapsed = time.time() - start_time
    qps = effective_samples / elapsed
    cpu = process.cpu_percent(interval=1)
    mem = process.memory_info().rss / 1024 ** 2
    return {"耗时": elapsed, "CPU占用": cpu, "内存占用(MB)": mem, "QPS": qps}

samples = 3000
before = simulate_detection(samples, with_filter=False)
after = simulate_detection(samples, with_filter=True)

print("=== 过滤前 ===")
for k, v in before.items():
    print(f"{k}: {v:.2f}")

print("\n=== 过滤后 ===")
for k, v in after.items():
    print(f"{k}: {v:.2f}")

metrics = list(before.keys())
before_values = [before[m] for m in metrics]
after_values = [after[m] for m in metrics]

x = range(len(metrics))
bar_width = 0.35

plt.figure(figsize=(8, 5))
plt.bar([i - bar_width/2 for i in x], before_values, width=bar_width, label='过滤前', color='orange')
plt.bar([i + bar_width/2 for i in x], after_values, width=bar_width, label='过滤后', color='green')

plt.xticks(x, metrics, fontsize=10)
plt.ylabel("指标值", fontsize=12)
plt.title("白流量过滤前后性能对比", fontsize=14)
plt.legend()
plt.tight_layout()
plt.savefig("performance_comparison.png")
plt.show()
