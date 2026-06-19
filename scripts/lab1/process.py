import re
import numpy as np
import pandas as pd
import os

# Tên file đầu vào của mày
win_input = 'BenchMark_Lab1.txt'
lin_input = 'Benchmark_lab1_on_linux.txt'
ops_per_run = 1000

# Mapping dung lượng
size_map = {
    '1KB': 1024, '4KB': 4096, '16KB': 16384, 
    '256KB': 262144, '1MB': 1048576, '8MB': 8388608
}

def process_and_export(input_file, output_csv, os_name):
    if not os.path.exists(input_file):
        print(f"[!] Không tìm thấy file: {input_file}")
        return

    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()

    results = []
    # Regex bắt đúng định dạng: mode_op_size = [1.2, 1.3...]
    pattern = r'([a-zA-Z0-9_]+)\s*=\s*\[(.*?)\]'
    
    for match in re.findall(pattern, content):
        parts = match[0].split('_')
        if len(parts) != 3: continue
        
        mode = parts[0].upper()
        op = 'Encrypt' if parts[1] == 'enc' else 'Decrypt'
        size_label = parts[2]
        
        # Parse mảng string thành mảng float
        data = np.array([float(x) for x in match[1].split(',') if x.strip()])
        n = len(data)
        if n == 0: continue
        
        # Tính toán các chỉ số thống kê
        mean = np.mean(data)
        median = np.median(data)
        stddev = np.std(data, ddof=1)
        ci95 = 1.96 * (stddev / np.sqrt(n))
        
        # Tính Throughput (MB/s)
        size_bytes = size_map.get(size_label, 0)
        total_mb = (size_bytes * ops_per_run) / (1024 * 1024)
        throughput = total_mb / (mean / 1000.0) if mean > 0 else 0
        
        results.append({
            'Algorithm': f"AES-{mode}",
            'Operation': op,
            'Size_Label': size_label,
            'Mean_ms': round(mean, 3),
            'Median_ms': round(median, 3),
            'StdDev_ms': round(stddev, 3),
            'CI95_ms': round(ci95, 3),
            'Throughput_MBs': round(throughput, 2)
        })

    if results:
        df = pd.DataFrame(results)
        # Sắp xếp lại cho dễ nhìn: Theo Dung lượng thực -> Thuật toán -> Thao tác
        df['Size_Bytes'] = df['Size_Label'].map(size_map)
        df = df.sort_values(by=['Size_Bytes', 'Algorithm', 'Operation']).drop(columns=['Size_Bytes'])
        
        # Xuất ra CSV
        df.to_csv(output_csv, index=False)
        print(f"[+] Đã xử lý {os_name} -> Xuất thành công: {output_csv}")
    else:
        print(f"[-] Lỗi: Không đọc được mảng dữ liệu nào từ {input_file}")

# Chạy độc lập cho 2 hệ điều hành
print("Đang xử lý dữ liệu Lab 1...")
process_and_export(win_input, 'Lab1_Stats_Windows.csv', 'Windows 11')
process_and_export(lin_input, 'Lab1_Stats_Linux.csv', 'Linux Ubuntu')
print("Xong!")