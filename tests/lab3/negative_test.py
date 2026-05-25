import os
import sys
import ctypes
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

crypto_lib = ctypes.CDLL(lib_path)
crypto_lib.rsatool_keygen.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
crypto_lib.rsatool_keygen.restype = ctypes.c_int
crypto_lib.rsatool_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
crypto_lib.rsatool_encrypt.restype = ctypes.c_int
crypto_lib.rsatool_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
crypto_lib.rsatool_decrypt.restype = ctypes.c_int

# ==========================================
# 2. LOGIC KIỂM THỬ NEGATIVE TESTS
# ==========================================
def print_status(test_name, passed, msg=""):
    status = "\033[92m[PASS]\033[0m" if passed else "\033[91m[FAIL]\033[0m"
    print(f"{status} {test_name}")
    if msg:
        print(f"       -> Lỗi trả về từ C++: {msg.strip()}")

def run_negative_tests():
    test_dir = os.path.abspath(os.path.join(current_script_dir, "negative_temp"))
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir, exist_ok=True)
    
    err_msg = ctypes.create_string_buffer(512)

    print("\n" + "="*70)
    print(" BẮT ĐẦU KIỂM THỬ CÁC RỦI RO BẢO MẬT (NEGATIVE TESTS)")
    print("="*70)

    # 1. CHUẨN BỊ MÔI TRƯỜNG
    print("[*] Đang sinh 2 cặp khóa RSA (Alice và Bob)...")
    alice_prefix = os.path.join(test_dir, "alice_key").encode('utf-8')
    bob_prefix = os.path.join(test_dir, "bob_key").encode('utf-8')
    
    crypto_lib.rsatool_keygen(3072, alice_prefix, b"pem", err_msg, 512)
    crypto_lib.rsatool_keygen(3072, bob_prefix, b"pem", err_msg, 512)

    alice_pub = os.path.join(test_dir, "alice_key_public.pem").encode('utf-8')
    alice_priv = os.path.join(test_dir, "alice_key_private.pem").encode('utf-8')
    bob_priv = os.path.join(test_dir, "bob_key_private.pem").encode('utf-8')

    # Dữ liệu nhỏ (Ép sử dụng Pure RSA)
    small_plain_file = os.path.join(test_dir, "secret_small.txt")
    with open(small_plain_file, "w") as f:
        f.write("Day la tai lieu mat, khong duoc doc trom!")
    b_small_plain = small_plain_file.encode('utf-8')

    # Dữ liệu lớn (Ép sử dụng Hybrid Encryption: Header + AES-GCM)
    large_plain_file = os.path.join(test_dir, "secret_large.txt")
    with open(large_plain_file, "w") as f:
        f.write("A" * 2048) # 2KB payload
    b_large_plain = large_plain_file.encode('utf-8')

    # ---------------------------------------------------------
    # TEST 1: SAI KHÓA (WRONG PRIVATE KEY)
    # ---------------------------------------------------------
    cipher_file_1 = os.path.join(test_dir, "cipher_t1.bin")
    b_cipher_1 = cipher_file_1.encode('utf-8')
    recover_file_1 = os.path.join(test_dir, "recover_t1.txt").encode('utf-8')

    crypto_lib.rsatool_encrypt(b_small_plain, alice_pub, b_cipher_1, b"Label", err_msg, 512)
    res_t1 = crypto_lib.rsatool_decrypt(b_cipher_1, bob_priv, recover_file_1, b"Label", err_msg, 512)
    print_status("Test 1: Giải mã bằng Private Key sai (Wrong private key)", res_t1 != 0, err_msg.value.decode('utf-8'))

    # ---------------------------------------------------------
    # TEST 2: SAI LABEL OAEP
    # ---------------------------------------------------------
    cipher_file_2 = os.path.join(test_dir, "cipher_t2.bin")
    b_cipher_2 = cipher_file_2.encode('utf-8')
    recover_file_2 = os.path.join(test_dir, "recover_t2.txt").encode('utf-8')

    crypto_lib.rsatool_encrypt(b_small_plain, alice_pub, b_cipher_2, b"Financial_Report", err_msg, 512)
    res_t2 = crypto_lib.rsatool_decrypt(b_cipher_2, alice_priv, recover_file_2, b"Marketing_Report", err_msg, 512)
    print_status("Test 2: Giải mã với OAEP Label bị sai (Wrong OAEP label)", res_t2 != 0, err_msg.value.decode('utf-8'))

    # ---------------------------------------------------------
    # TEST 3: DỮ LIỆU BỊ SỬA ĐỔI - PURE RSA (ALTERED RSA CIPHERTEXT)
    # ---------------------------------------------------------
    cipher_file_3 = os.path.join(test_dir, "cipher_t3.bin")
    b_cipher_3 = cipher_file_3.encode('utf-8')
    recover_file_3 = os.path.join(test_dir, "recover_t3.txt").encode('utf-8')

    crypto_lib.rsatool_encrypt(b_small_plain, alice_pub, b_cipher_3, b"Label", err_msg, 512)
    
    with open(cipher_file_3, "rb+") as f:
        f.seek(-5, os.SEEK_END)
        byte = f.read(1)
        f.seek(-5, os.SEEK_END)
        f.write(bytes([byte[0] ^ 0xFF]))

    res_t3 = crypto_lib.rsatool_decrypt(b_cipher_3, alice_priv, recover_file_3, b"Label", err_msg, 512)
    print_status("Test 3: Giải mã file Pure RSA Ciphertext đã bị chỉnh sửa", res_t3 != 0, err_msg.value.decode('utf-8'))

    # ---------------------------------------------------------
    # TEST 4: DỮ LIỆU BỊ SỬA ĐỔI - HYBRID (ALTERED AES-GCM CIPHERTEXT)
    # ---------------------------------------------------------
    cipher_file_4 = os.path.join(test_dir, "cipher_t4.bin")
    b_cipher_4 = cipher_file_4.encode('utf-8')
    recover_file_4 = os.path.join(test_dir, "recover_t4.txt").encode('utf-8')

    crypto_lib.rsatool_encrypt(b_large_plain, alice_pub, b_cipher_4, b"Label", err_msg, 512)
    
    # Sửa đổi Ciphertext ở phần cuối file (Tương đương AES-GCM Tag hoặc Data)
    with open(cipher_file_4, "rb+") as f:
        f.seek(-2, os.SEEK_END)
        byte = f.read(1)
        f.seek(-2, os.SEEK_END)
        f.write(bytes([byte[0] ^ 0xFF]))

    res_t4 = crypto_lib.rsatool_decrypt(b_cipher_4, alice_priv, recover_file_4, b"Label", err_msg, 512)
    print_status("Test 4: Giải mã AES-GCM Ciphertext đã bị chỉnh sửa (Tag failure)", res_t4 != 0, err_msg.value.decode('utf-8'))

    # ---------------------------------------------------------
    # TEST 5: ENVELOPE HEADER BỊ SỬA ĐỔI (TAMPERED ENVELOPE HEADER)
    # ---------------------------------------------------------
    cipher_file_5 = os.path.join(test_dir, "cipher_t5.bin")
    b_cipher_5 = cipher_file_5.encode('utf-8')
    recover_file_5 = os.path.join(test_dir, "recover_t5.txt").encode('utf-8')

    crypto_lib.rsatool_encrypt(b_large_plain, alice_pub, b_cipher_5, b"Label", err_msg, 512)
    
    # Đọc file và sửa đổi thông tin JSON Header
    with open(cipher_file_5, "rb") as f:
        content = bytearray(f.read())
    
    # Tìm kiếm chuỗi "hash": "SHA-256" và cố tình đổi 1 ký tự
    hash_idx = content.find(b'"hash": "SHA-256"')
    if hash_idx != -1:
        content[hash_idx + 10] = ord(b'3') # Biến thành "SHA-356"
        
    with open(cipher_file_5, "wb") as f:
        f.write(content)

    res_t5 = crypto_lib.rsatool_decrypt(b_cipher_5, alice_priv, recover_file_5, b"Label", err_msg, 512)
    print_status("Test 5: Giải mã với JSON Envelope Header bị can thiệp", res_t5 != 0, err_msg.value.decode('utf-8'))


    print("="*70)
    print("[*] Hoàn tất Negative Tests. Nếu tất cả đều [PASS] -> Phần mềm an toàn!")
    
    # ---------------------------------------------------------
    # LỰA CHỌN DỌN DẸP "IN BIÊN LAI"
    # ---------------------------------------------------------
    while True:
        try:
            choice = input("\n[?] Bạn có muốn giữ lại thư mục chứa các file test (negative_temp) để xem lại không? (y/n): ").strip().lower()
            if choice in ['n', 'no', '']:
                shutil.rmtree(test_dir)
                print(f"[*] Đã dọn dẹp sạch sẽ thư mục rác: {test_dir}")
                break
            elif choice in ['y', 'yes']:
                print(f"[*] Đã giữ lại thư mục: {test_dir} để bạn kiểm tra.")
                break
            else:
                print("[!] Vui lòng chỉ nhập 'y' (Có) hoặc 'n' (Không/Nhấn Enter).")
        except Exception as e:
            print(f"[!] Lỗi khi dọn dẹp: {e}")
            break

if __name__ == "__main__":
    if os.name == 'nt':
        os.system('color')
    run_negative_tests()