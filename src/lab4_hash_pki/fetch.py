import urllib.request
import zipfile
import io
import json

# Link tải thẳng từ trang web chính phủ Mỹ (NIST CAVP)
NIST_URL = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip"

def main():
    print(f"[*] Đang kéo file ZIP chứa test vectors chuẩn từ NIST CSRC...")
    print(f"[*] Link: {NIST_URL}")
    
    try:
        req = urllib.request.urlopen(NIST_URL)
        zip_data = io.BytesIO(req.read())
    except Exception as e:
        print(f"[!] Lỗi khi tải dữ liệu từ web: {e}")
        return

    output_tests = []
    tc_id = 1
    
    with zipfile.ZipFile(zip_data) as z:
        # Trong file zip của NIST có sẵn thư mục "shabytetestvectors"
        # Bóc 2 file SHA256 và SHA512 ra làm test mẫu
        files_to_parse = [
            ("shabytetestvectors/SHA256ShortMsg.rsp", "sha256"),
            ("shabytetestvectors/SHA512ShortMsg.rsp", "sha512")
        ]
        
        for filepath, algo in files_to_parse:
            print(f"[*] Đang parse file {filepath}...")
            
            # Đọc file .rsp dưới dạng string
            content = z.read(filepath).decode('utf-8')
            
            length = 0
            msg = ""
            for line in content.splitlines():
                line = line.strip()
                
                if line.startswith("Len ="):
                    length = int(line.split("=")[1].strip())
                    
                elif line.startswith("Msg ="):
                    msg = line.split("=")[1].strip()
                    # NIST biểu diễn chuỗi rỗng là "00" với Len = 0, ta cần chuẩn hóa lại
                    if length == 0:
                        msg = "" 
                        
                elif line.startswith("MD ="):
                    md = line.split("=")[1].strip()
                    
                    # Đẩy dữ liệu vào mảng theo đúng form của hashtool
                    output_tests.append({
                        "tcId": str(tc_id),
                        "algo": algo,
                        "msg": msg,
                        "md": md
                    })
                    tc_id += 1
                    msg = "" # Reset message cho lần lặp tiếp theo

    out_file = "nist_hash_kats.json"
    with open(out_file, "w") as f:
        json.dump(output_tests, f, indent=4)
        
    print(f"[+] Đã bóc tách thành công {len(output_tests)} test cases chuẩn của NIST vào file '{out_file}'!")

if __name__ == "__main__":
    main()