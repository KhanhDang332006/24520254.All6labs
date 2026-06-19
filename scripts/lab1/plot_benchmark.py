import pandas as pd
import matplotlib.pyplot as plt

def plot_os_metrics(csv_file, os_name, output_filename):
    # Đọc dữ liệu
    df = pd.read_csv(csv_file)
    
    # Định nghĩa thứ tự sắp xếp cho trục X (Size_Label)
    size_order = ['1KB', '4KB', '16KB', '256KB', '1MB', '8MB']
    df['Size_Label'] = pd.Categorical(df['Size_Label'], categories=size_order, ordered=True)
    df = df.sort_values('Size_Label')
    
    # Tạo figure gồm 4 biểu đồ con (2 hàng, 2 cột)
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle(f'Latency & Throughput - {os_name}', fontsize=20, fontweight='bold', y=1.02)
    
    operations = ['Encrypt', 'Decrypt']
    metrics = [('Mean_ms', 'Latency (ms)'), ('Throughput_MBs', 'Throughput (MB/s)')]
    
    # Vẽ lần lượt từng biểu đồ
    for i, (metric, ylabel) in enumerate(metrics):
        for j, op in enumerate(operations):
            ax = axes[i, j]
            
            # Lọc dữ liệu theo từng thao tác (Encrypt/Decrypt)
            data = df[df['Operation'] == op]
            
            # Chuyển đổi dữ liệu để trục X là Size, các đường là Thuật toán
            pivot_data = data.pivot(index='Size_Label', columns='Algorithm', values=metric)
            
            # Vẽ biểu đồ đường
            pivot_data.plot(kind='line', marker='o', ax=ax, linewidth=2, markersize=6)
            
            # Định dạng biểu đồ
            ax.set_title(f'{op} {ylabel.split(" ")[0]}', fontsize=14)
            ax.set_xlabel('File Size', fontsize=12)
            ax.set_ylabel(ylabel, fontsize=12)
            ax.grid(True, linestyle='--', alpha=0.7)
            
            # Chỉ hiển thị chú thích (Legend) ở góc biểu đồ trên cùng bên phải cho gọn
            if i == 0 and j == 1:
                ax.legend(title='Algorithm', bbox_to_anchor=(1.05, 1), loc='upper left')
            else:
                ax.get_legend().remove()
    
    # Căn chỉnh bố cục và lưu file
    plt.tight_layout()
    plt.savefig(output_filename, bbox_inches='tight', dpi=150)
    plt.close()

# Vẽ và lưu biểu đồ cho cả Windows và Linux (Hãy đảm bảo 2 file csv nằm cùng thư mục với script code)
plot_os_metrics('Lab1_Stats_Windows.csv', 'Windows', 'windows_metrics.png')
plot_os_metrics('Lab1_Stats_Linux.csv', 'Linux', 'linux_metrics.png')

print("Đã vẽ và lưu biểu đồ thành công!")