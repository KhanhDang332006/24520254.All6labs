import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

# Tên file CSV
linux_file = 'lab4_benchmark_results_ForLinux.csv'
win_file = 'lab4_benchmark_results_ForWindow.csv'

if not os.path.exists(linux_file) or not os.path.exists(win_file):
    print("[!] Không tìm thấy đủ 2 file CSV. Hãy kiểm tra lại thư mục!")
    sys.exit(1)

# Đọc dữ liệu
df_linux = pd.read_csv(linux_file)
df_linux['OS'] = 'Linux (Ubuntu LTS)'
df_linux['File_Suffix'] = 'Linux'

df_win = pd.read_csv(win_file)
df_win['OS'] = 'Windows 11'
df_win['File_Suffix'] = 'Windows'

df = pd.concat([df_win, df_linux])

colors = {'sha256': '#1f77b4', 'sha512': '#ff7f0e', 'sha3-256': '#2ca02c', 'sha3-512': '#d62728'}
markers = {'sha256': 'o', 'sha512': 's', 'sha3-256': '^', 'sha3-512': 'D'}

for os_name in df['OS'].unique():
    sub_df = df[df['OS'] == os_name]
    file_suffix = sub_df['File_Suffix'].iloc[0]
    
    # ==========================================
    # ĐỒ THỊ 1: THROUGHPUT (IN-MEMORY vs STREAMING)
    # ==========================================
    fig, axes = plt.subplots(1, 2, figsize=(14, 6), sharey=True)
    fig.suptitle(f'Hash Throughput on {os_name} (MB/s)', fontsize=16, fontweight='bold')
    
    for idx, mode in enumerate(['In-Memory', 'Streaming']):
        ax = axes[idx]
        mode_df = sub_df[sub_df['Mode'] == mode]
        
        for algo in ['sha256', 'sha512', 'sha3-256', 'sha3-512']:
            algo_df = mode_df[mode_df['Algorithm'] == algo].sort_values('Size_MB')
            if algo_df.empty: continue
            ax.plot(algo_df['Size_MB'], algo_df['Throughput_MBs'], marker=markers[algo], 
                    label=algo.upper(), color=colors[algo], linewidth=2.5, markersize=8)
            
        ax.set_xscale('log')
        ax.set_xticks([1, 100, 1024])
        ax.set_xticklabels(['1 MB', '100 MB', '1 GB'])
        ax.set_title(f'Mode: {mode}', fontsize=14)
        ax.set_xlabel('Payload Size [Log Scale]', fontsize=12)
        if idx == 0: ax.set_ylabel('Throughput (MB/s)', fontsize=12)
        ax.grid(True, which="both", ls="--", alpha=0.6)
        ax.legend(fontsize=10)
        
    plt.tight_layout()
    thr_filename = f'Lab4_Throughput_{file_suffix}.png'
    plt.savefig(thr_filename, dpi=300)
    plt.close()
    print(f"[+] Đã lưu biểu đồ: {thr_filename}")

    # ==========================================
    # ĐỒ THỊ 2: LATENCY VỚI 95% CI (IN-MEMORY vs STREAMING)
    # ==========================================
    fig, axes = plt.subplots(1, 2, figsize=(14, 6), sharey=True)
    fig.suptitle(f'Hash Latency on {os_name} (95% CI)', fontsize=16, fontweight='bold')
    
    for idx, mode in enumerate(['In-Memory', 'Streaming']):
        ax = axes[idx]
        mode_df = sub_df[sub_df['Mode'] == mode]
        
        for algo in ['sha256', 'sha512', 'sha3-256', 'sha3-512']:
            algo_df = mode_df[mode_df['Algorithm'] == algo].sort_values('Size_MB')
            if algo_df.empty: continue
            ax.errorbar(algo_df['Size_MB'], algo_df['Mean_ms'], yerr=algo_df['CI95_ms'], 
                        marker=markers[algo], capsize=5, label=algo.upper(), color=colors[algo], 
                        linewidth=2.5, elinewidth=1.5, markersize=8)
            
        ax.set_xscale('log')
        ax.set_yscale('log')
        ax.set_xticks([1, 100, 1024])
        ax.set_xticklabels(['1 MB', '100 MB', '1 GB'])
        ax.set_title(f'Mode: {mode}', fontsize=14)
        ax.set_xlabel('Payload Size [Log Scale]', fontsize=12)
        if idx == 0: ax.set_ylabel('Latency (ms) [Log Scale]', fontsize=12)
        ax.grid(True, which="both", ls="--", alpha=0.6)
        ax.legend(fontsize=10)
        
    plt.tight_layout()
    lat_filename = f'Lab4_Latency_{file_suffix}.png'
    plt.savefig(lat_filename, dpi=300)
    plt.close()
    print(f"[+] Đã lưu biểu đồ: {lat_filename}")