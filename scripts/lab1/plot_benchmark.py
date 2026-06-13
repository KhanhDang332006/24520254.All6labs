import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os

def process_file(filepath, os_name):
    results = []
    # Khai báo kích thước file chuẩn sang Bytes
    size_map = {'1KB': 1024, '4KB': 4096, '16KB': 16384, '256KB': 262144, '1MB': 1048576, '8MB': 8388608}
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Dùng regex để quét các mảng dữ liệu (VD: ctr_enc_1KB = [1.939, ...])
    matches = re.findall(r'([a-z]+)_(enc|dec)_([0-9]+[KMB]+)\s*=\s*(\[[0-9.,\s]+\])', content)
    
    for mode, op, size_str, arr_str in matches:
        if op != 'enc': continue # Lọc lấy kết quả mã hóa (Encrypt) để so sánh thống nhất
        
        vals = eval(arr_str)
        if not vals: continue
        
        N = len(vals)
        mean_time = np.mean(vals)
        median_time = np.median(vals)
        std_time = np.std(vals, ddof=1)
        
        # Khoảng tin cậy 95% (95% CI)
        ci95 = 1.96 * (std_time / np.sqrt(N))
        
        # Dữ liệu hiện tại là tổng thời gian (ms) cho 1000 operations
        ops_per_run = 1000
        latency_per_op = mean_time / ops_per_run
        ci95_per_op = ci95 / ops_per_run
        
        size_bytes = size_map[size_str]
        
        # Tính Throughput (MB/s)
        throughput = (size_bytes / 1048576.0) / (latency_per_op / 1000.0)
        
        results.append({
            'OS': os_name,
            'Mode': mode.upper(),
            'Size_Label': size_str,
            'Size_KB': size_bytes / 1024,
            'Mean_ms': latency_per_op,
            'Median_ms': median_time / ops_per_run,
            'StdDev_ms': std_time / ops_per_run,
            'CI95_ms': ci95_per_op,
            'Throughput_MBs': throughput
        })
    return results

# 1. Đọc và hợp nhất dữ liệu từ 2 file
win_data = process_file('BenchMark_Lab1.txt', 'Windows 11 (MinGW)')
lin_data = process_file('Benchmark_lab1_on_linux.txt', 'Linux (Ubuntu)')
df = pd.DataFrame(win_data + lin_data)

# Xuất ra file CSV
csv_out = 'lab1_processed_stats.csv'
df.to_csv(csv_out, index=False)
print(f"[+] Đã xuất file thống kê: {csv_out}")

# 2. Vẽ 4 biểu đồ riêng biệt
df_plot = df[df['Mode'].isin(['CBC', 'CTR', 'GCM'])]
colors = {'CBC': '#1f77b4', 'CTR': '#2ca02c', 'GCM': '#d62728'}
markers = {'CBC': 'o', 'CTR': 's', 'GCM': '^'}

os_list = ['Windows 11 (MinGW)', 'Linux (Ubuntu)']

for os_name in os_list:
    sub_df = df_plot[df_plot['OS'] == os_name]
    os_file_suffix = "Windows" if "Windows" in os_name else "Linux"
    
    # --- ĐỒ THỊ 1: THROUGHPUT ---
    plt.figure(figsize=(10, 6))
    for mode in ['CBC', 'CTR', 'GCM']:
        m_df = sub_df[sub_df['Mode'] == mode].sort_values('Size_KB')
        if m_df.empty: continue
        
        plt.plot(m_df['Size_KB'], m_df['Throughput_MBs'], marker=markers[mode], 
                 label=mode, color=colors[mode], linewidth=2.5, markersize=8)
        
    plt.xscale('log')
    plt.title(f'Throughput trên {os_name}', fontsize=16, fontweight='bold')
    plt.xlabel('Payload Size (KB) [Log Scale]', fontsize=14)
    plt.ylabel('Throughput (MB/s)', fontsize=14)
    plt.grid(True, which="both", ls="--", alpha=0.6)
    plt.legend(fontsize=12)
    plt.tight_layout()
    
    thr_filename = f'Lab1_Throughput_{os_file_suffix}.png'
    plt.savefig(thr_filename, dpi=300)
    plt.close()
    print(f"[+] Đã lưu biểu đồ: {thr_filename}")
    
    # --- ĐỒ THỊ 2: LATENCY ---
    plt.figure(figsize=(10, 6))
    for mode in ['CBC', 'CTR', 'GCM']:
        m_df = sub_df[sub_df['Mode'] == mode].sort_values('Size_KB')
        if m_df.empty: continue
        
        plt.errorbar(m_df['Size_KB'], m_df['Mean_ms'], yerr=m_df['CI95_ms'], 
                     marker=markers[mode], capsize=5, label=mode, color=colors[mode], 
                     linewidth=2.5, elinewidth=1.5, markersize=8)
        
    plt.xscale('log')
    plt.yscale('log')
    plt.title(f'Latency per Op trên {os_name} (95% CI)', fontsize=16, fontweight='bold')
    plt.xlabel('Payload Size (KB) [Log Scale]', fontsize=14)
    plt.ylabel('Latency (ms) [Log Scale]', fontsize=14)
    plt.grid(True, which="both", ls="--", alpha=0.6)
    plt.legend(fontsize=12)
    plt.tight_layout()
    
    lat_filename = f'Lab1_Latency_{os_file_suffix}.png'
    plt.savefig(lat_filename, dpi=300)
    plt.close()
    print(f"[+] Đã lưu biểu đồ: {lat_filename}")