import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

# Tên file CSV
linux_file = 'lab2_benchmark_results_forLinux.csv'
win_file = 'lab2_benchmark_resultsForWindow.csv'

if not os.path.exists(linux_file) or not os.path.exists(win_file):
    print("[!] Không tìm thấy đủ 2 file CSV. Hãy kiểm tra lại thư mục!")
    sys.exit(1)

# Đọc dữ liệu
df_linux = pd.read_csv(linux_file)
df_linux['OS'] = 'Linux (Ubuntu LTS)'
df_linux['File_Suffix'] = 'Linux'

df_win = pd.read_csv(win_file)
df_win['OS'] = 'Windows 11 (MinGW)'
df_win['File_Suffix'] = 'Windows'

# Gộp dữ liệu
df = pd.concat([df_win, df_linux])

# Ánh xạ Size_Label sang Megabytes (MB) để vẽ biểu đồ log scale
size_mapping = {'1 MiB': 1, '100 MiB': 100, '1 GiB': 1024}
df['Size_MB'] = df['Size_Label'].map(size_mapping)
df = df.sort_values(by=['OS', 'Size_MB'])

colors = {'Windows 11 (MinGW)': '#1f77b4', 'Linux (Ubuntu LTS)': '#ff7f0e'}
markers = {'Windows 11 (MinGW)': 'o', 'Linux (Ubuntu LTS)': 's'}

os_list = df['OS'].unique()

# Vẽ 4 biểu đồ riêng biệt
for os_name in os_list:
    subset = df[df['OS'] == os_name]
    file_suffix = subset['File_Suffix'].iloc[0]
    
    # ==========================================
    # ĐỒ THỊ 1: THROUGHPUT
    # ==========================================
    plt.figure(figsize=(8, 6))
    plt.plot(subset['Size_MB'], subset['Throughput_MBs'], marker=markers[os_name], 
             label='AES-128 CTR (Pure C++)', color=colors[os_name], linewidth=2.5, markersize=8)

    plt.xscale('log')
    plt.xticks([1, 100, 1024], ['1 MiB', '100 MiB', '1 GiB'])
    
    # Cố định trục Y tùy theo mức hiệu năng để nhìn biểu đồ đẹp hơn
    min_y = subset['Throughput_MBs'].min() - 2
    max_y = subset['Throughput_MBs'].max() + 2
    plt.ylim(min_y, max_y) 
    
    plt.title(f'Throughput trên {os_name}', fontsize=16, fontweight='bold')
    plt.xlabel('Payload Size [Log Scale]', fontsize=14)
    plt.ylabel('Throughput (MB/s)', fontsize=14)
    plt.grid(True, which="both", ls="--", alpha=0.6)
    plt.legend(fontsize=12)
    plt.tight_layout()

    thr_filename = f'Lab2_Throughput_{file_suffix}.png'
    plt.savefig(thr_filename, dpi=300)
    plt.close()
    print(f"[+] Đã lưu biểu đồ: {thr_filename}")

    # ==========================================
    # ĐỒ THỊ 2: LATENCY VỚI 95% CI
    # ==========================================
    plt.figure(figsize=(8, 6))
    plt.errorbar(subset['Size_MB'], subset['Mean_ms'], yerr=subset['CI95_ms'], 
                 marker=markers[os_name], capsize=5, label='AES-128 CTR (Pure C++)', color=colors[os_name], 
                 linewidth=2.5, elinewidth=1.5, markersize=8)

    plt.xscale('log')
    plt.yscale('log')
    plt.xticks([1, 100, 1024], ['1 MiB', '100 MiB', '1 GiB'])
    
    plt.title(f'Latency per Payload trên {os_name}', fontsize=16, fontweight='bold')
    plt.xlabel('Payload Size [Log Scale]', fontsize=14)
    plt.ylabel('Total Execution Time (ms) [Log Scale]', fontsize=14)
    plt.grid(True, which="both", ls="--", alpha=0.6)
    plt.legend(fontsize=12)
    plt.tight_layout()

    lat_filename = f'Lab2_Latency_{file_suffix}.png'
    plt.savefig(lat_filename, dpi=300)
    plt.close()
    print(f"[+] Đã lưu biểu đồ: {lat_filename}")