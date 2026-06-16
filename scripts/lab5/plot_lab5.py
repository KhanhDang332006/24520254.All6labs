import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
import sys

# Tên file CSV
linux_file = 'lab5_benchmark_results_forLinux.csv'
win_file = 'lab5_benchmark_results_forWindow.csv'

if not os.path.exists(linux_file) or not os.path.exists(win_file):
    print("[!] Không tìm thấy đủ 2 file CSV. Hãy kiểm tra lại thư mục!")
    sys.exit(1)

# Đọc dữ liệu
df_linux = pd.read_csv(linux_file)
df_linux['OS'] = 'Linux (Ubuntu LTS)'

df_win = pd.read_csv(win_file)
df_win['OS'] = 'Windows 11 (MinGW)'

df = pd.concat([df_win, df_linux])

colors = {'ECDSA-P256': '#1f77b4', 'ECDSA-P384': '#ff7f0e', 'RSA-PSS-3072': '#2ca02c'}
markers = {'ECDSA-P256': 'o', 'ECDSA-P384': 's', 'RSA-PSS-3072': '^'}

# ==========================================
# ĐỒ THỊ 1: KEYGEN LATENCY (BAR CHART - LOG SCALE)
# ==========================================
df_kg = df[df['Operation'] == 'Keygen'].copy()
if not df_kg.empty:
    plt.figure(figsize=(10, 6))
    
    labels = df_kg['Algorithm'].unique()
    x = np.arange(len(labels))
    width = 0.35
    
    win_means = [df_kg[(df_kg['OS'] == 'Windows 11 (MinGW)') & (df_kg['Algorithm'] == alg)]['Mean_ms'].values[0] for alg in labels]
    lin_means = [df_kg[(df_kg['OS'] == 'Linux (Ubuntu LTS)') & (df_kg['Algorithm'] == alg)]['Mean_ms'].values[0] for alg in labels]
    
    plt.bar(x - width/2, win_means, width, label='Windows 11', color='#1f77b4', edgecolor='black')
    plt.bar(x + width/2, lin_means, width, label='Linux (Ubuntu)', color='#ff7f0e', edgecolor='black')
    
    plt.yscale('log') # Bắt buộc dùng Log scale vì RSA quá lâu so với ECDSA
    plt.ylabel('Keygen Latency (ms) [Log Scale]', fontsize=14)
    plt.title('Key Generation Performance Comparison', fontsize=16, fontweight='bold')
    plt.xticks(x, labels, fontsize=12)
    plt.legend(fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    
    plt.savefig('Lab5_Keygen_Compare.png', dpi=300)
    plt.close()
    print("[+] Đã lưu biểu đồ: Lab5_Keygen_Compare.png")

# Chuẩn bị dữ liệu cho Line charts
size_mapping = {'1 KiB': 1, '16 KiB': 16, '1 MiB': 1024, '8 MiB': 8192}
df_op = df[df['Operation'] != 'Keygen'].copy()
df_op['Size_KB'] = df_op['Size_Label'].map(size_mapping)

def plot_line_chart(operation, filename, ylabel):
    sub_df = df_op[df_op['Operation'] == operation]
    if sub_df.empty: return
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 6), sharey=True)
    fig.suptitle(f'{operation} Performance vs Payload Size', fontsize=16, fontweight='bold')
    
    for idx, os_name in enumerate(['Windows 11 (MinGW)', 'Linux (Ubuntu LTS)']):
        ax = axes[idx]
        os_df = sub_df[sub_df['OS'] == os_name]
        
        for algo in colors.keys():
            algo_df = os_df[os_df['Algorithm'] == algo].sort_values('Size_KB')
            if algo_df.empty: continue
            ax.errorbar(algo_df['Size_KB'], algo_df['Mean_ms'], yerr=algo_df['CI95_ms'], 
                        marker=markers[algo], capsize=5, label=algo, color=colors[algo], 
                        linewidth=2.5, elinewidth=1.5, markersize=8)
            
        ax.set_xscale('log')
        ax.set_yscale('log')
        ax.set_xticks([1, 16, 1024, 8192])
        ax.set_xticklabels(['1 KiB', '16 KiB', '1 MiB', '8 MiB'])
        ax.set_title(f'{os_name}', fontsize=14)
        ax.set_xlabel('Payload Size [Log Scale]', fontsize=12)
        if idx == 0: ax.set_ylabel(ylabel, fontsize=12)
        ax.grid(True, which="both", ls="--", alpha=0.6)
        ax.legend(fontsize=10)
        
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    plt.close()
    print(f"[+] Đã lưu biểu đồ: {filename}")

# ==========================================
# ĐỒ THỊ 2 & 3: SIGN VÀ VERIFY (LINE CHARTS)
# ==========================================
plot_line_chart('Sign', 'Lab5_Sign_Latency_Compare.png', 'Sign Latency (ms) [Log Scale]')
plot_line_chart('Verify', 'Lab5_Verify_Latency_Compare.png', 'Verify Latency (ms) [Log Scale]')