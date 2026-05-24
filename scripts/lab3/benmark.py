import os
import sys
import ctypes
import time
import csv
import shutil

# ==========================================
# 1. NẠP THƯ VIỆN C-API
# ==========================================
current_script_dir = os.path.dirname(os.path.abspath(__file__))

if os.name == 'nt':
    dll_dir = os.path.abspath(os.path.join(current_script_dir, "..","..", "build", "src", "lab3_rsa_hybrid"))
    path_1 = os.path.join(dll_dir, "liblab3_dll.dll")
    path_2 = os.path.join(dll_dir, "lab3_dll.dll")
    lib_path = path_1 if os.path.exists(path_1) else path_2

    paths_to_add = []
    paths_to_add.extend(os.environ.get("PATH", "").split(os.pathsep))
    for p in paths_to_add:
        if os.path.exists(p) and os.path.isdir(p):
            try:
                os.add_dll_directory(p)
            except Exception:
                pass
else:
    lib_path = os.path.abspath(os.path.join(current_script_dir, "..","..", "build", "src", "lab3_rsa_hybrid", "liblab3_dll.so"))

if not os.path.exists(lib_path):
    print(f"[!] LỖI: Không tìm thấy thư viện tại: {lib_path}")
    sys.exit(1)

try:
    crypto_lib = ctypes.CDLL(lib_path)
except OSError as e:
    print(f"[!] Lỗi nạp thư viện: {e}")
    sys.exit(1)

crypto_lib.rsatool_keygen.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
crypto_lib.rsatool_keygen.restype = ctypes.c_int
crypto_lib.rsatool_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
crypto_lib.rsatool_encrypt.restype = ctypes.c_int
crypto_lib.rsatool_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
crypto_lib.rsatool_decrypt.restype = ctypes.c_int

# ==========================================
# 2. LOGIC BENCHMARK
# ==========================================
def generate_dummy_file(filepath, size_mb):
    print(f"   -> Đang tạo file giả định {size_mb}MB...")
    chunk_size = 1024 * 1024
    with open(filepath, "wb") as f:
        for _ in range(size_mb):
            f.write(os.urandom(chunk_size))

def run_benchmark():
    print("\n" + "="*65)
    print(" BẮT ĐẦU ĐO HIỆU NĂNG HYBRID ENCRYPTION (RSA + AES-GCM)")
    print("="*65)

    # Vòng lặp bắt người dùng nhập đúng số 3072 hoặc 4096
    while True:
        try:
            user_input = input("[?] Nhập độ dài khóa RSA muốn test (3072 hoặc 4096): ").strip()
            bits = int(user_input)
            if bits not in [3072, 4096]:
                print("[!] Vui lòng chỉ nhập 3072 hoặc 4096.\n")
                continue
            break
        except ValueError:
            print("[!] Lỗi: Vui lòng nhập một số nguyên.\n")

    test_dir = os.path.abspath(os.path.join(current_script_dir, "..", "test", "benchmark_temp"))
    os.makedirs(test_dir, exist_ok=True)
    
    # Đặt tên file kết quả theo số bits để không bị ghi đè
    csv_out = os.path.join(current_script_dir, f"benchmark_results_{bits}.csv")
    err_msg = ctypes.create_string_buffer(512)

    sizes_mb = [1, 10, 50, 100]
    results = []

    print(f"\n[*] Đang thiết lập và kiểm thử với khóa RSA {bits}-bit:")
    
    # Sinh khóa
    key_prefix = os.path.join(test_dir, f"bench_key_{bits}")
    crypto_lib.rsatool_keygen(bits, key_prefix.encode('utf-8'), b"pem", err_msg, 512)
    pub_key = f"{key_prefix}_public.pem".encode('utf-8')
    priv_key = f"{key_prefix}_private.pem".encode('utf-8')

    for size in sizes_mb:
        plain_file = os.path.join(test_dir, f"plain_{size}MB.dat")
        cipher_file = os.path.join(test_dir, f"cipher_{size}MB.bin")
        recover_file = os.path.join(test_dir, f"recover_{size}MB.dat")
        
        b_plain = plain_file.encode('utf-8')
        b_cipher = cipher_file.encode('utf-8')
        b_recover = recover_file.encode('utf-8')

        generate_dummy_file(plain_file, size)

        # Đo thời gian Mã hóa
        start_enc = time.perf_counter()
        res_enc = crypto_lib.rsatool_encrypt(b_plain, pub_key, b_cipher, b"benchmark", err_msg, 512)
        end_enc = time.perf_counter()
        enc_time = (end_enc - start_enc) * 1000
        
        if res_enc != 0:
            print(f"[!] Lỗi mã hóa: {err_msg.value.decode()}")
            continue

        # Đo thời gian Giải mã
        start_dec = time.perf_counter()
        res_dec = crypto_lib.rsatool_decrypt(b_cipher, priv_key, b_recover, b"benchmark", err_msg, 512)
        end_dec = time.perf_counter()
        dec_time = (end_dec - start_dec) * 1000
        
        if res_dec != 0:
            print(f"[!] Lỗi giải mã: {err_msg.value.decode()}")
            continue

        print(f"      [+] File {size:3}MB | Encrypt: {enc_time:7.2f} ms | Decrypt: {dec_time:7.2f} ms")
        
        results.append({
            "RSA Key (Bits)": bits,
            "File Size (MB)": size,
            "Encrypt Time (ms)": round(enc_time, 2),
            "Decrypt Time (ms)": round(dec_time, 2)
        })

        os.remove(plain_file)
        os.remove(cipher_file)
        os.remove(recover_file)

    # Xuất file CSV
    with open(csv_out, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["RSA Key (Bits)", "File Size (MB)", "Encrypt Time (ms)", "Decrypt Time (ms)"])
        writer.writeheader()
        writer.writerows(results)
    
    print("\n" + "="*65)
    print(f"[*] Hoàn tất! Dữ liệu đã được xuất ra: {csv_out}")

# ---------------------------------------------------------
    # DỌN DẸP THƯ MỤC TẠM
    # ---------------------------------------------------------
    while True:
        try:
            choice = input("\n[?] Bạn có muốn giữ lại thư mục chứa các file test (benchmark_temp) để xem lại không? (y/n): ").strip().lower()
            # Mặc định (nhấn Enter) hoặc 'n' là Không (Xóa folder)
            if choice in ['n', 'no', '']:
                if os.path.exists(test_dir):
                    shutil.rmtree(test_dir)
                    print(f"[*] Đã dọn dẹp sạch sẽ thư mục: {test_dir}")
                break
            # 'y' là Có (Giữ lại)
            elif choice in ['y', 'yes']:
                print(f"[*] Đã giữ lại thư mục: {test_dir} để bạn kiểm tra.")
                break
            else:
                print("[!] Vui lòng chỉ nhập 'y' (Có) hoặc 'n' (Không/Nhấn Enter).")
        except Exception as e:
            print(f"[!] Lỗi khi dọn dẹp: {e}")
            break

if __name__ == "__main__":
    run_benchmark()