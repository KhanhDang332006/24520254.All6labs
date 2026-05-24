import sys
import os
import ctypes

# Bắt lỗi import PySide6 để UX mượt mà cho người chấm
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, 
        QMessageBox, QTabWidget, QFormLayout, QLineEdit, QComboBox, 
        QFileDialog, QLabel, QHBoxLayout, QTextEdit
    )
except ImportError:
    print("\n[!] LỖI: Không tìm thấy thư viện PySide6.")
    print("[*] Để chạy được giao diện GUI, vui lòng cài đặt bằng lệnh sau:")
    print("    pip install PySide6")
    print("    hoặc: pip install -r requirements.txt\n")
    sys.exit(1)

# ==========================================
# 1. CẤU HÌNH ĐƯỜNG DẪN THƯ VIỆN ĐA NỀN TẢNG (THE ULTIMATE WAY)
# ==========================================
current_script_dir = os.path.dirname(os.path.abspath(__file__))

if os.name == 'nt':
    dll_dir = os.path.abspath(os.path.join(current_script_dir, "..", "build", "src", "lab3_rsa_hybrid"))
    
    # 1. Tự động kiểm tra cả 2 trường hợp tên file do CMake sinh ra
    path_1 = os.path.join(dll_dir, "liblab3_dll.dll")
    path_2 = os.path.join(dll_dir, "lab3_dll.dll")
    lib_path = path_1 if os.path.exists(path_1) else path_2

    # 2. Lưới dự phòng (Fallback): Quét biến PATH và add_dll_directory để hốt file libwinpthread-1.dll bị sót
    paths_to_add = [
        r"C:\msys64\mingw64\bin",
        r"D:\Tai_lieu\UIT_Document\HK2_2025_2026\NT219_MatMaHoc\Labs\CryptoLib",
        r"D:\Tai_lieu\UIT_Document\HK2_2025_2026\NT219_MatMaHoc\Labs\CryptoLib\lib",
        r"D:\Tai_lieu\UIT_Document\HK2_2025_2026\NT219_MatMaHoc\Labs\CryptoLib\bin"
    ]
    # Lấy toàn bộ biến môi trường PATH của hệ thống
    paths_to_add.extend(os.environ.get("PATH", "").split(os.pathsep))
    
    for p in paths_to_add:
        if os.path.exists(p) and os.path.isdir(p):
            try:
                os.add_dll_directory(p)
            except Exception:
                pass # Bỏ qua các đường dẫn rác của hệ điều hành
else:
    # Trên Linux thì mọi thứ lúc nào cũng mượt mà, không cần xử lý rườm rà
    lib_path = os.path.abspath(os.path.join(current_script_dir, "..", "build", "src", "lab3_rsa_hybrid", "liblab3_dll.so"))

# 3. Tiến hành nạp DLL
if not os.path.exists(lib_path):
    print(f"[!] LỖI: Không tìm thấy file thư viện tại: {lib_path}")
    print("[*] Vui lòng chạy lệnh CMake build trước khi mở giao diện!")
    sys.exit(1)

try:
    crypto_lib = ctypes.CDLL(lib_path)
except OSError as e:
    print(f"\n[!] LỖI HỆ THỐNG KHI NẠP THƯ VIỆN C/C++: {e}")
    print(f"[*] Đã tìm thấy file DLL chính tại: {lib_path}")
    print("[*] TUY NHIÊN, Windows không thể tìm thấy các thư viện phụ thuộc (dependencies) của nó.")
    print("[*] (Ví dụ: libwinpthread-1.dll, libgcc_s_seh-1.dll hoặc các file .dll của Crypto++)")
    print("[*] Vui lòng kiểm tra lại biến môi trường PATH hoặc thêm các file dll thiếu vào cùng thư mục với script này.\n")
    sys.exit(1)

# Map prototypes từ C-API trong rsatool.cpp
crypto_lib.rsatool_keygen.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
crypto_lib.rsatool_keygen.restype = ctypes.c_int

crypto_lib.rsatool_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
crypto_lib.rsatool_encrypt.restype = ctypes.c_int

crypto_lib.rsatool_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
crypto_lib.rsatool_decrypt.restype = ctypes.c_int

# ==========================================
# 2. GIAO DIỆN CHÍNH (SỬ DỤNG TABS CHỨC NĂNG)
# ==========================================
class CryptoGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RSATOOL - Hybrid RSA-OAEP / AES-GCM")
        self.setMinimumSize(550, 400)

        # Sử dụng QTabWidget phân chia theo Usage cấu trúc CLI
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.init_tab_keygen()
        self.init_tab_crypto(is_encrypt=True)
        self.init_tab_crypto(is_encrypt=False)

    def init_tab_keygen(self):
        widget = QWidget()
        layout = QFormLayout()

        self.cb_bits = QComboBox()
        self.cb_bits.addItems(["3072", "4096"])
        layout.addRow("Modulus Size (Bits):", self.cb_bits)

        self.txt_prefix = QLineEdit("server")
        layout.addRow("File Prefix:", self.txt_prefix)

        self.cb_key_format = QComboBox()
        self.cb_key_format.addItems(["both", "pem", "der"])
        layout.addRow("Output Format:", self.cb_key_format)

        btn_run = QPushButton("Generate Key Pair")
        btn_run.clicked.connect(self.run_keygen)
        layout.addRow("", btn_run)

        widget.setLayout(layout)
        self.tabs.addTab(widget, "Key Generation")

    def run_keygen(self):
        bits = int(self.cb_bits.currentText())
        prefix = self.txt_prefix.text().strip()
        fmt = self.cb_key_format.currentText()

        if not prefix:
            QMessageBox.warning(self, "Lỗi dữ liệu", "Vui lòng nhập Prefix tên file!")
            return

        err_msg = ctypes.create_string_buffer(256)
        res = crypto_lib.rsatool_keygen(bits, prefix.encode('utf-8'), fmt.encode('utf-8'), err_msg, 256)

        if res == 0:
            QMessageBox.information(self, "Thành công", f"Đã sinh cặp khóa thành công với tiền tố: {prefix}")
        else:
            QMessageBox.critical(self, "Thất bại", f"Lỗi: {err_msg.value.decode('utf-8', errors='ignore')}")

    def init_tab_crypto(self, is_encrypt=True):
        widget = QWidget()
        layout = QFormLayout()

        key_layout = QHBoxLayout()
        txt_key = QLineEdit()
        btn_browse_key = QPushButton("Browse...")
        btn_browse_key.clicked.connect(lambda: self.browse_file(txt_key, "Key Files (*.pem *.der);;All Files (*)"))
        key_layout.addWidget(txt_key)
        key_layout.addWidget(btn_browse_key)
        layout.addRow("RSA Key File:", key_layout)

        cb_in_mode = QComboBox()
        cb_in_mode.addItems(["Plain Text (Chuỗi)" if is_encrypt else "Cipher Text (Chuỗi)", "Từ File (.bin, .txt, ...)"])
        layout.addRow("Chế độ đầu vào:", cb_in_mode)

        txt_input_data = QTextEdit()
        txt_input_data.setPlaceholderText("Nhập nội dung vào đây...")
        layout.addRow("Dữ liệu đầu vào:", txt_input_data)

        file_in_layout = QHBoxLayout()
        txt_file_in = QLineEdit()
        btn_browse_in = QPushButton("Browse...")
        btn_browse_in.clicked.connect(lambda: self.browse_file(txt_file_in, "All Files (*)"))
        file_in_layout.addWidget(txt_file_in)
        file_in_layout.addWidget(btn_browse_in)
        
        lbl_file_in = QLabel("File đầu vào:")
        layout.addRow(lbl_file_in, file_in_layout)
        
        txt_file_in.hide()
        btn_browse_in.hide()
        lbl_file_in.hide()

        def toggle_input(index):
            if index == 0:
                txt_input_data.show()
                txt_file_in.hide()
                btn_browse_in.hide()
                lbl_file_in.hide()
            else:
                txt_input_data.hide()
                txt_file_in.show()
                btn_browse_in.show()
                lbl_file_in.show()

        cb_in_mode.currentIndexChanged.connect(toggle_input)

        out_layout = QHBoxLayout()
        txt_file_out = QLineEdit()
        btn_browse_out = QPushButton("Save to...")
        btn_browse_out.clicked.connect(lambda: self.save_file(txt_file_out))
        out_layout.addWidget(txt_file_out)
        out_layout.addWidget(btn_browse_out)
        layout.addRow("File kết quả:", out_layout)

        txt_label = QLineEdit()
        txt_label.setPlaceholderText("Không bắt buộc (Optional)")
        layout.addRow("OAEP Parameter / Label:", txt_label)

        btn_execute = QPushButton("Thực hiện Mã hóa" if is_encrypt else "Thực hiện Giải mã")
        btn_execute.clicked.connect(lambda: self.run_crypto(
            is_encrypt, txt_key, cb_in_mode, txt_input_data, txt_file_in, txt_file_out, txt_label
        ))
        layout.addRow("", btn_execute)

        widget.setLayout(layout)
        self.tabs.addTab(widget, "Encryption" if is_encrypt else "Decryption")

    def run_crypto(self, is_encrypt, txt_key, cb_mode, txt_data, txt_fin, txt_fout, txt_lbl):
        key_path = txt_key.text().strip()
        file_out = txt_fout.text().strip()
        label = txt_lbl.text().strip()

        if not key_path or not os.path.exists(key_path):
            QMessageBox.warning(self, "Lỗi", "Đường dẫn khóa RSA không hợp lệ hoặc không tồn tại!")
            return
        if not file_out:
            QMessageBox.warning(self, "Lỗi", "Vui lòng chọn đường dẫn cho file kết quả đầu ra!")
            return

        temp_file_created = False
        if cb_mode.currentIndex() == 0:
            input_content = txt_data.toPlainText()
            file_in = os.path.abspath(os.path.join(current_script_dir, "temp_gui_input.dat"))
            with open(file_in, "wb" if not is_encrypt else "w", encoding=None if not is_encrypt else "utf-8") as f:
                if is_encrypt:
                    f.write(input_content)
                else:
                    import base64
                    try:
                        f.write(base64.b64decode(input_content))
                    except Exception:
                        QMessageBox.critical(self, "Lỗi", "Chuỗi mã hóa không đúng định dạng Base64 hợp lệ!")
                        return
            temp_file_created = True
        else:
            file_in = txt_fin.text().strip()
            if not file_in or not os.path.exists(file_in):
                QMessageBox.warning(self, "Lỗi", "File đầu vào không hợp lệ!")
                return

        err_msg = ctypes.create_string_buffer(512)
        b_file_in = file_in.encode('utf-8')
        b_key_path = key_path.encode('utf-8')
        b_file_out = file_out.encode('utf-8')
        b_label = label.encode('utf-8') if label else None

        if is_encrypt:
            res = crypto_lib.rsatool_encrypt(b_file_in, b_key_path, b_file_out, b_label, err_msg, 512)
        else:
            res = crypto_lib.rsatool_decrypt(b_file_in, b_key_path, b_file_out, b_label, err_msg, 512)

        if temp_file_created and os.path.exists(file_in):
            os.remove(file_in)

        if res == 0:
            QMessageBox.information(self, "Thành công", f"Quá trình xử lý thành công!\nKết quả lưu tại: {file_out}")
        else:
            QMessageBox.critical(self, "Thất bại", f"Lỗi xử lý: {err_msg.value.decode('utf-8', errors='ignore')}")

    def browse_file(self, target_line_edit, file_filter):
        filename, _ = QFileDialog.getOpenFileName(self, "Select File", "", file_filter)
        if filename:
            target_line_edit.setText(os.path.abspath(filename))

    def save_file(self, target_line_edit):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Output File As", "", "All Files (*)")
        if filename:
            target_line_edit.setText(os.path.abspath(filename))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CryptoGUI()
    window.show()
    sys.exit(app.exec())
