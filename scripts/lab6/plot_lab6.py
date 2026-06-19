import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
import sys

# Load files
linux_file = 'lab6_benchmark_results_forLinux.csv'
win_file = 'lab6_benchmark_results_forWindow.csv'

if not os.path.exists(linux_file) or not os.path.exists(win_file):
    print("[!] Không tìm thấy đủ 2 file CSV. Hãy kiểm tra lại thư mục!")
    sys.exit(1)

df_linux = pd.read_csv(linux_file)
df_linux['OS'] = 'Linux (Ubuntu LTS)'

df_win = pd.read_csv(win_file)
df_win['OS'] = 'Windows 11 (MinGW)'

df = pd.concat([df_win, df_linux])

# ==========================================
# ĐỒ THỊ 1: ML-KEM PERFORMANCE (BAR CHART)
# ==========================================
df_kem = df[df['Algorithm'].str.contains('ML-KEM')].copy()
if not df_kem.empty:
    fig, axes = plt.subplots(1, 2, figsize=(14, 6), sharey=True)
    fig.suptitle('ML-KEM Performance Comparison (Latency)', fontsize=16, fontweight='bold')
    
    for idx, os_name in enumerate(['Windows 11 (MinGW)', 'Linux (Ubuntu LTS)']):
        ax = axes[idx]
        os_df = df_kem[df_kem['OS'] == os_name]
        
        labels = ['Keygen', 'Encaps', 'Decaps']
        x = np.arange(len(labels))
        width = 0.35
        
        kem512 = [os_df[(os_df['Operation']==op) & (os_df['Algorithm']=='ML-KEM-512')]['Mean_ms'].values[0] for op in labels]
        kem768 = [os_df[(os_df['Operation']==op) & (os_df['Algorithm']=='ML-KEM-768')]['Mean_ms'].values[0] for op in labels]
        
        ax.bar(x - width/2, kem512, width, label='ML-KEM-512', color='#1f77b4', edgecolor='black')
        ax.bar(x + width/2, kem768, width, label='ML-KEM-768', color='#ff7f0e', edgecolor='black')
        
        ax.set_title(os_name, fontsize=14)
        ax.set_ylabel('Latency (ms)', fontsize=12)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=12)
        ax.legend()
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        
    plt.tight_layout()
    plt.savefig('Lab6_MLKEM_Compare.png', dpi=300)
    plt.close()
    print("[+] Đã lưu biểu đồ: Lab6_MLKEM_Compare.png")

# ==========================================
# ĐỒ THỊ 2: ML-DSA KEYGEN (BAR CHART)
# ==========================================
df_dsa_kg = df[(df['Algorithm'].str.contains('ML-DSA')) & (df['Operation'] == 'Keygen')].copy()
if not df_dsa_kg.empty:
    plt.figure(figsize=(8, 6))
    labels = df_dsa_kg['Algorithm'].unique()
    x = np.arange(len(labels))
    width = 0.35
    
    win_means = [df_dsa_kg[(df_dsa_kg['OS'] == 'Windows 11 (MinGW)') & (df_dsa_kg['Algorithm'] == alg)]['Mean_ms'].values[0] for alg in labels]
    lin_means = [df_dsa_kg[(df_dsa_kg['OS'] == 'Linux (Ubuntu LTS)') & (df_dsa_kg['Algorithm'] == alg)]['Mean_ms'].values[0] for alg in labels]
    
    plt.bar(x - width/2, win_means, width, label='Windows 11', color='#1f77b4', edgecolor='black')
    plt.bar(x + width/2, lin_means, width, label='Linux (Ubuntu)', color='#ff7f0e', edgecolor='black')
    
    plt.ylabel('Keygen Latency (ms)', fontsize=14)
    plt.title('ML-DSA Key Generation Latency', fontsize=16, fontweight='bold')
    plt.xticks(x, labels, fontsize=12)
    plt.legend(fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    
    plt.savefig('Lab6_MLDSA_Keygen_Compare.png', dpi=300)
    plt.close()
    print("[+] Đã lưu biểu đồ: Lab6_MLDSA_Keygen_Compare.png")

# ==========================================
# ĐỒ THỊ 3 & 4: ML-DSA SIGN/VERIFY (LINE CHARTS)
# ==========================================
size_mapping = {'1 KiB': 1, '16 KiB': 16, '1 MiB': 1024, '8 MiB': 8192}
df_dsa_op = df[(df['Algorithm'].str.contains('ML-DSA')) & (df['Operation'] != 'Keygen')].copy()
df_dsa_op['Size_KB'] = df_dsa_op['Size_Label'].map(size_mapping)

colors = {'ML-DSA-44': '#1f77b4', 'ML-DSA-65': '#ff7f0e'}
markers = {'ML-DSA-44': 'o', 'ML-DSA-65': 's'}

def plot_mldsa_line(operation, filename, ylabel):
    sub_df = df_dsa_op[df_dsa_op['Operation'] == operation]
    if sub_df.empty: return
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 6), sharey=True)
    fig.suptitle(f'ML-DSA {operation} Performance vs Payload Size', fontsize=16, fontweight='bold')
    
    for idx, os_name in enumerate(['Windows 11 (MinGW)', 'Linux (Ubuntu LTS)']):
        ax = axes[idx]
        os_df = sub_df[sub_df['OS'] == os_name]
        for alg in colors.keys():
            alg_df = os_df[os_df['Algorithm'] == alg].sort_values('Size_KB')
            if alg_df.empty: continue
            ax.errorbar(alg_df['Size_KB'], alg_df['Mean_ms'], yerr=alg_df['CI95_ms'], 
                        marker=markers[alg], capsize=5, label=alg, color=colors[alg], 
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

plot_mldsa_line('Sign', 'Lab6_MLDSA_Sign_Latency.png', 'Sign Latency (ms) [Log Scale]')
plot_mldsa_line('Verify', 'Lab6_MLDSA_Verify_Latency.png', 'Verify Latency (ms) [Log Scale]')