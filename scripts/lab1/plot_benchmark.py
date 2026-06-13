import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

# Tìm file CSV (Nó sẽ nằm ở thư mục root khi chạy CMake exe)
csv_path = os.path.join(os.getcwd(), 'lab1_benchmark_results.csv')
if not os.path.exists(csv_path):
    print("[!] Không tìm thấy file CSV. Hãy chạy file benchmark_lab1.exe trước!")
    sys.exit(1)

df = pd.read_csv(csv_path)

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
modes = df['Mode'].unique()
colors = {'AES-CBC': '#1f77b4', 'AES-CTR': '#2ca02c', 'AES-GCM': '#d62728'}
markers = {'AES-CBC': 'o', 'AES-CTR': 's', 'AES-GCM': '^'}

# Đồ thị 1: Thông lượng (Throughput)
for mode in modes:
    subset = df[df['Mode'] == mode]
    ax1.plot(subset['Size_KB'], subset['Throughput_MBs'], marker=markers[mode], 
             label=mode, color=colors[mode], linewidth=2)

ax1.set_xscale('log')
ax1.set_xlabel('Payload Size (KB) [Log Scale]')
ax1.set_ylabel('Throughput (MB/s)')
ax1.set_title('Symmetric Encryption Throughput Comparison')
ax1.grid(True, which="both", ls="--", alpha=0.5)
ax1.legend()

# Đồ thị 2: Độ trễ (Latency) với Thanh sai số (95% CI Error Bars)
for mode in modes:
    subset = df[df['Mode'] == mode]
    ax2.errorbar(subset['Size_KB'], subset['Mean_ms'], yerr=subset['CI95_ms'], 
                 marker=markers[mode], capsize=4, label=mode, color=colors[mode], 
                 linewidth=2, elinewidth=1.5)

ax2.set_xscale('log')
ax2.set_yscale('log')
ax2.set_xlabel('Payload Size (KB) [Log Scale]')
ax2.set_ylabel('Latency per Operation (ms) [Log Scale]')
ax2.set_title('Latency Comparison (with 95% CI)')
ax2.grid(True, which="both", ls="--", alpha=0.5)
ax2.legend()

plt.tight_layout()
out_img = os.path.join(os.getcwd(), 'Lab1_Performance_Plots.png')
plt.savefig(out_img, dpi=300)
print(f"[+] Đã vẽ đồ thị thành công! Lưu tại: {out_img}")