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
# 1. CẤU HÌNH ĐƯỜNG DẪN THƯ VIỆN ĐA NỀN TẢNG (THE PRO WAY)
# ==========================================
current_script_dir = os.path.dirname(os.path.abspath(__file__))

# Phân loại Hệ điều hành (nt = Windows, posix = Linux/macOS)
if os.name == 'nt':
    lib_filename = "liblab3_dll.dll" # Trên Windows dùng .dll
else:
    lib_filename = "liblab3_dll.so" # Trên Linux dùng .so

lib_path = os.path.abspath(os.path.join(current_script_dir, "..", "build", "src", "lab3_rsa_hybrid", lib_filename))

try:
    # Nạp thư viện động.
    # Nhờ Cmake link tĩnh (-static) thư viện C++ vào trong, không cần gọi os.add_dll_directory() trên Windows nữa.
    # Trên Linux, hệ điều hành tự động lo việc load dependency một cách mượt mà.
    crypto_lib = ctypes.CDLL(lib_path)
except OSError as e:
    print(f"[!] Lỗi hệ thống khi nạp thư viện C/C++: {e}")
    print(f"[*] Đường dẫn đang tìm kiếm: {lib_path}")
    print("[*] Vui lòng đảm bảo bạn đã chạy lệnh CMake build trước.")
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

    # ------------------------------------------------------
    # TAB 1: KEYGEN
    # ------------------------------------------------------
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

    # ------------------------------------------------------
    # TAB 2 & 3: ENCRYPT / DECRYPT
    # ------------------------------------------------------
    def init_tab_crypto(self, is_encrypt=True):
        widget = QWidget()
        layout = QFormLayout()

        # Chọn Khóa
        key_layout = QHBoxLayout()
        txt_key = QLineEdit()
        btn_browse_key = QPushButton("Browse...")
        btn_browse_key.clicked.connect(lambda: self.browse_file(txt_key, "Key Files (*.pem *.der);;All Files (*)"))
        key_layout.addWidget(txt_key)
        key_layout.addWidget(btn_browse_key)
        layout.addRow("RSA Key File:", key_layout)

        # Chọn Input Mode (Text hoặc File)
        cb_in_mode = QComboBox()
        cb_in_mode.addItems(["Plain Text (Chuỗi)" if is_encrypt else "Cipher Text (Chuỗi)", "Từ File (.bin, .txt, ...)"])
        layout.addRow("Chế độ đầu vào:", cb_in_mode)

        # Vùng nhập Text (Ẩn/Hiện dựa vào Input Mode)
        txt_input_data = QTextEdit()
        txt_input_data.setPlaceholderText("Nhập nội dung vào đây...")
        layout.addRow("Dữ liệu đầu vào:", txt_input_data)

        # Vùng chọn File Đầu vào (Ẩn/Hiện dựa vào Input Mode)
        file_in_layout = QHBoxLayout()
        txt_file_in = QLineEdit()
        btn_browse_in = QPushButton("Browse...")
        btn_browse_in.clicked.connect(lambda: self.browse_file(txt_file_in, "All Files (*)"))
        file_in_layout.addWidget(txt_file_in)
        file_in_layout.addWidget(btn_browse_in)
        
        lbl_file_in = QLabel("File đầu vào:")
        layout.addRow(lbl_file_in, file_in_layout)
        
        # Mặc định ẩn chế độ File, dùng Text trước
        txt_file_in.hide()
        btn_browse_in.hide()
        lbl_file_in.hide()

        # Sự kiện đổi chế độ Input Mode
        def toggle_input(index):
            if index == 0:  # Chế độ Text
                txt_input_data.show()
                txt_file_in.hide()
                btn_browse_in.hide()
                lbl_file_in.hide()
            else:           # Chế độ File
                txt_input_data.hide()
                txt_file_in.show()
                btn_browse_in.show()
                lbl_file_in.show()

        cb_in_mode.currentIndexChanged.connect(toggle_input)

        # File đầu ra
        out_layout = QHBoxLayout()
        txt_file_out = QLineEdit()
        btn_browse_out = QPushButton("Save to...")
        btn_browse_out.clicked.connect(lambda: self.save_file(txt_file_out))
        out_layout.addWidget(txt_file_out)
        out_layout.addWidget(btn_browse_out)
        layout.addRow("File kết quả:", out_layout)

        # Label xác thực của OAEP / AES-GCM
        txt_label = QLineEdit()
        txt_label.setPlaceholderText("Không bắt buộc (Optional)")
        layout.addRow("OAEP Parameter / Label:", txt_label)

        # Nút thực thi chính
        btn_execute = QPushButton("Thực hiện Mã hóa" if is_encrypt else "Thực hiện Giải mã")
        btn_execute.clicked.connect(lambda: self.run_crypto(
            is_encrypt, txt_key, cb_in_mode, txt_input_data, txt_file_in, txt_file_out, txt_label
        ))
        layout.addRow("", btn_execute)

        widget.setLayout(layout)
        self.tabs.addTab(widget, "Encryption" if is_encrypt else "Decryption")

    # ------------------------------------------------------
    # LOGIC XỬ LÝ MÃ HÓA / GIẢI MÃ LIÊN KẾT C-API
    # ------------------------------------------------------
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

        # Đồng bộ hóa dữ liệu Text tạm thời vào một file ẩn nếu người dùng chọn chế độ gõ Text trực tiếp
        # Vì hàm `rsatool_encrypt` trong file .cpp gốc nhận tham số là file path (`InputMode::FILE`)
        temp_file_created = False
        if cb_mode.currentIndex() == 0:  # Chế độ nhập Chuỗi (Text)
            input_content = txt_data.toPlainText()
            file_in = os.path.abspath(os.path.join(current_script_dir, "temp_gui_input.dat"))
            with open(file_in, "wb" if not is_encrypt else "w", encoding=None if not is_encrypt else "utf-8") as f:
                if is_encrypt:
                    f.write(input_content)
                else:
                    # Nếu giải mã từ chuỗi Base64 nhập trực tiếp, đưa định dạng về dạng thô cho hàm xử lý
                    import base64
                    try:
                        f.write(base64.b64decode(input_content))
                    except Exception:
                        QMessageBox.critical(self, "Lỗi", "Chuỗi mã hóa không đúng định dạng Base64 hợp lệ!")
                        return
            temp_file_created = True
        else:  # Chế độ File
            file_in = txt_fin.text().strip()
            if not file_in or not os.path.exists(file_in):
                QMessageBox.warning(self, "Lỗi", "File đầu vào không hợp lệ!")
                return

        err_msg = ctypes.create_string_buffer(512)
        
        # Chuyển đổi encode chuỗi sang bytes để truyền vào C-API
        b_file_in = file_in.encode('utf-8')
        b_key_path = key_path.encode('utf-8')
        b_file_out = file_out.encode('utf-8')
        b_label = label.encode('utf-8') if label else None

        # Gọi hàm tương ứng từ thư viện của giảng viên
        if is_encrypt:
            res = crypto_lib.rsatool_encrypt(b_file_in, b_key_path, b_file_out, b_label, err_msg, 512)
        else:
            res = crypto_lib.rsatool_decrypt(b_file_in, b_key_path, b_file_out, b_label, err_msg, 512)

        # Xóa file tạm sau khi nạp nếu có tạo
        if temp_file_created and os.path.exists(file_in):
            os.remove(file_in)

        if res == 0:
            QMessageBox.information(self, "Thành công", f"Quá trình xử lý thành công!\nKết quả lưu tại: {file_out}")
        else:
            QMessageBox.critical(self, "Thất bại", f"Lỗi xử lý: {err_msg.value.decode('utf-8', errors='ignore')}")

    # Helper Utils để mở hộp thoại hệ thống chọn File
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
