import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

def parse_lab3_file(filepath, os_name):
    results = []
    if not os.path.exists(filepath):
        print(f"[!] Không tìm thấy file: {filepath}")
        return results
        
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    current_algo = ""
    for line in lines:
        # Bắt tên thuật toán (Ví dụ: "RSA-3072", "Hybrid Encryption - 1 MB")
        match_algo = re.search(r'\[\*\] Benchmarking (.*?)\s*\(', line)
        if match_algo:
            current_algo = match_algo.group(1).strip()
            continue
            
        # Bắt các chỉ số thống kê (Mean, CI) cho Keygen, Encrypt, Decrypt, Latency
        match_stat = re.search(r'-\s+([\w\s]+?)\s*:\s*Mean = ([\d.]+)\s*ms.*?95% CI = \[([\d.]+),\s*([\d.]+)\]', line)
        if match_stat and current_algo:
            op = match_stat.group(1).strip()
            mean = float(match_stat.group(2))
            ci_low = float(match_stat.group(3))
            ci_high = float(match_stat.group(4))
            ci_err = (ci_high - ci_low) / 2
            
            results.append({
                'OS': os_name,
                'Algorithm': current_algo,
                'Operation': op,
                'Value': mean,
                'CI_err': ci_err,
                'Metric': 'Latency (ms)'
            })
            
        # Bắt thông lượng (Throughput) cho Hybrid
        match_thpt = re.search(r'-\s+Throughput\s*:\s*([\d.]+)\s*MB/s', line)
        if match_thpt and current_algo:
            thpt = float(match_thpt.group(1))
            results.append({
                'OS': os_name,
                'Algorithm': current_algo,
                'Operation': 'Throughput',
                'Value': thpt,
                'CI_err': 0, # Throughput hiện tại code C++ không tính CI
                'Metric': 'Throughput (MB/s)'
            })
            
    return results

# 1. Nạp dữ liệu
win_data = parse_lab3_file('Databenchmark_lab3_forWindow.txt', 'Windows 11')
lin_data = parse_lab3_file('Databenchmark_lab3_forLinux.txt', 'Linux (Ubuntu)')

df = pd.DataFrame(win_data + lin_data)
if df.empty:
    print("[!] Không tìm thấy dữ liệu hợp lệ. Hãy kiểm tra lại file txt.")
    sys.exit(1)

# Xuất ra file CSV
df.to_csv('lab3_parsed_stats.csv', index=False)
print("[+] Đã xuất bảng thống kê ra: lab3_parsed_stats.csv")

colors = {'Windows 11': '#1f77b4', 'Linux (Ubuntu)': '#ff7f0e'}

# ==========================================
# 2. VẼ BIỂU ĐỒ RSA TÁCH BIỆT (BAR CHARTS)
# ==========================================
df_rsa = df[df['Algorithm'].str.contains('RSA', case=False, na=False)]

if not df_rsa.empty:
    for op in ['Keygen', 'Encrypt', 'Decrypt']:
        df_op = df_rsa[df_rsa['Operation'] == op]
        if df_op.empty: continue
        
        plt.figure(figsize=(8, 6))
        labels = sorted(df_op['Algorithm'].unique()) # RSA-3072, RSA-4096
        
        x = np.arange(len(labels))
        width = 0.35
        win_means, win_err, lin_means, lin_err = [], [], [], []
        
        for alg in labels:
            w_val = df_op[(df_op['OS'] == 'Windows 11') & (df_op['Algorithm'] == alg)]
            win_means.append(w_val['Value'].values[0] if not w_val.empty else 0)
            win_err.append(w_val['CI_err'].values[0] if not w_val.empty else 0)
            
            l_val = df_op[(df_op['OS'] == 'Linux (Ubuntu)') & (df_op['Algorithm'] == alg)]
            lin_means.append(l_val['Value'].values[0] if not l_val.empty else 0)
            lin_err.append(l_val['CI_err'].values[0] if not l_val.empty else 0)
            
        plt.bar(x - width/2, win_means, width, yerr=win_err, label='Windows 11 (MinGW)', color=colors['Windows 11'], capsize=5, edgecolor='black')
        plt.bar(x + width/2, lin_means, width, yerr=lin_err, label='Linux (Ubuntu LTS)', color=colors['Linux (Ubuntu)'], capsize=5, edgecolor='black')
        
        plt.ylabel('Latency (ms)', fontsize=14)
        plt.title(f'RSA {op} Performance Comparison', fontsize=16, fontweight='bold')
        plt.xticks(x, labels, fontsize=12)
        plt.legend(fontsize=12)
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        
        img_name = f'Lab3_RSA_{op}_Compare.png'
        plt.savefig(img_name, dpi=300)
        plt.close()
        print(f"[+] Đã lưu biểu đồ: {img_name}")

# ==========================================
# 3. VẼ BIỂU ĐỒ HYBRID (LINE CHARTS)
# ==========================================
df_hybrid = df[df['Algorithm'].str.contains('Hybrid', case=False, na=False)]

if not df_hybrid.empty:
    def get_size_mb(algo_str):
        if '100 MB' in algo_str: return 100.0
        if '1 MB' in algo_str: return 1.0
        if '1 KB' in algo_str: return 0.001
        return 0.0
        
    df_hybrid['Size_MB'] = df_hybrid['Algorithm'].apply(get_size_mb)
    
    # 3.1 Vẽ Line Chart cho Latency
    df_lat = df_hybrid[df_hybrid['Operation'] == 'Latency']
    if not df_lat.empty:
        plt.figure(figsize=(8, 6))
        for os_name in ['Windows 11', 'Linux (Ubuntu)']:
            df_os = df_lat[df_lat['OS'] == os_name].sort_values('Size_MB')
            if df_os.empty: continue
            
            plt.errorbar(df_os['Size_MB'], df_os['Value'], yerr=df_os['CI_err'], 
                         marker='o', capsize=5, label=os_name, color=colors[os_name], 
                         linewidth=2.5, elinewidth=1.5, markersize=8)
                         
        plt.xscale('log')
        plt.yscale('log')
        plt.xticks([0.001, 1, 100], ['1 KB', '1 MB', '100 MB'])
        plt.ylabel('Latency (ms) [Log Scale]', fontsize=14)
        plt.xlabel('Payload Size [Log Scale]', fontsize=14)
        plt.title('Hybrid Encryption Latency (Overall)', fontsize=16, fontweight='bold')
        plt.grid(True, which="both", ls="--", alpha=0.5)
        plt.legend(fontsize=12)
        plt.tight_layout()
        
        img_name = 'Lab3_Hybrid_Latency_Compare.png'
        plt.savefig(img_name, dpi=300)
        plt.close()
        print(f"[+] Đã lưu biểu đồ: {img_name}")

    # 3.2 Vẽ Line Chart cho Throughput
    df_thpt = df_hybrid[df_hybrid['Operation'] == 'Throughput']
    if not df_thpt.empty:
        plt.figure(figsize=(8, 6))
        for os_name in ['Windows 11', 'Linux (Ubuntu)']:
            df_os = df_thpt[df_thpt['OS'] == os_name].sort_values('Size_MB')
            if df_os.empty: continue
            
            plt.plot(df_os['Size_MB'], df_os['Value'], marker='s', 
                     label=os_name, color=colors[os_name], linewidth=2.5, markersize=8)
                         
        plt.xscale('log')
        plt.xticks([0.001, 1, 100], ['1 KB', '1 MB', '100 MB'])
        plt.ylabel('AES Throughput (MB/s)', fontsize=14)
        plt.xlabel('Payload Size [Log Scale]', fontsize=14)
        plt.title('Hybrid Encryption AES-GCM Throughput', fontsize=16, fontweight='bold')
        plt.grid(True, which="both", ls="--", alpha=0.5)
        plt.legend(fontsize=12)
        plt.tight_layout()
        
        img_name = 'Lab3_Hybrid_Throughput_Compare.png'
        plt.savefig(img_name, dpi=300)
        plt.close()
        print(f"[+] Đã lưu biểu đồ: {img_name}")