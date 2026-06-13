import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# URL các bộ test vectors chuẩn từ Google Wycheproof (NIST compliant)
WYCHEPROOF_URLS = {
    "gcm": "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/aes_gcm_test.json",
    "ccm": "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/aes_ccm_test.json",
    "cbc": "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/aes_cbc_pkcs5_test.json"
}

def fetch_and_format_vectors():
    flat_kats = []
    
    for mode, url in WYCHEPROOF_URLS.items():
        print(f"[*] Đang tải test vectors cho mode AES-{mode.upper()}...")
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, context=ctx) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                # Trích xuất từ cấu trúc lồng nhau của Wycheproof
                for group in data.get("testGroups", []):
                    # Bỏ qua các test case có kích thước key/iv không tiêu chuẩn để dễ test
                    if group.get("keySize") not in [128, 192, 256]:
                        continue
                        
                    for test in group.get("tests", []):
                        # Chỉ lấy các test case hợp lệ (valid)
                        if test.get("result") == "valid":
                            formatted_tc = {
                                "test_name": f"Wycheproof_AES_{mode.upper()}_TC{test['tcId']}",
                                "mode": mode,
                                "key": test["key"],
                                "iv": test["iv"],
                                "plaintext": test["msg"],
                                "ciphertext": test["ct"]
                            }
                            
                            # Thêm các trường đặc thù cho AEAD
                            if mode in ["gcm", "ccm"]:
                                formatted_tc["aad"] = test.get("aad", "")
                                formatted_tc["tag"] = test.get("tag", "")
                                
                            flat_kats.append(formatted_tc)
                            
                            # Lấy tối đa 15 test case mỗi mode để tránh file json quá nặng 
                            if len([t for t in flat_kats if t["mode"] == mode]) >= 100:
                                break
                    if len([t for t in flat_kats if t["mode"] == mode]) >= 100:
                        break
        except Exception as e:
            print(f"[!] Lỗi khi tải {mode}: {e}")

    output_file = "vectors.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(flat_kats, f, indent=4)
        
    print(f"\n[+] Đã tạo thành công '{output_file}' với {len(flat_kats)} test cases.")
    print(f"[+] Lệnh để test: ./aestool --kat {output_file}")

if __name__ == "__main__":
    fetch_and_format_vectors()