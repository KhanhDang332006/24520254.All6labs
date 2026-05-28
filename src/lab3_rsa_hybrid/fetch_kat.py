import urllib.request
import urllib.error
import json
import ssl
import base64

# Bỏ qua xác thực SSL nếu môi trường mạng nội bộ filter
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Danh sách các URL dự phòng (từ kho C2SP mới nhất và Google cũ)
urls = [
    "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/rsa_oaep_3072_sha256_mgf1sha256_test.json",
    "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors/rsa_oaep_3072_sha256_mgf1sha256_test.json",
    "https://raw.githubusercontent.com/google/wycheproof/master/testvectors/rsa_oaep_3072_sha256_mgf1sha256_test.json"
]

data = None

print("[*] Bắt đầu tải dữ liệu KAT...")
for url in urls:
    try:
        print(f" -> Đang thử tải từ: {url.split('/')[-3] + '/' + url.split('/')[-2]}")
        req = urllib.request.urlopen(url, context=ctx)
        data = json.loads(req.read().decode('utf-8'))
        print(" [+] Tải thành công từ Github!")
        break
    except urllib.error.HTTPError:
        continue
    except Exception as e:
        print(f" [-] Lỗi mạng: {e}")

# Fallback dự phòng cuối cùng: Mirror của BoringSSL (chứa mã base64, cực kỳ ổn định)
if data is None:
    try:
        print(" -> Đang thử tải qua BoringSSL Mirror...")
        url_bssl = "https://boringssl.googlesource.com/boringssl/+/master/third_party/wycheproof_testvectors/rsa_oaep_3072_sha256_mgf1sha256_test.json?format=TEXT"
        req = urllib.request.urlopen(url_bssl, context=ctx)
        b64_data = req.read()
        data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
        print(" [+] Tải thành công từ BoringSSL!")
    except Exception as e:
        print(f" [-] Lỗi BoringSSL: {e}")

if data is None:
    print("[!] FATAL: Không thể tải dữ liệu từ bất kỳ nguồn nào. Vui lòng kiểm tra lại mạng.")
    exit(1)

output_vectors = []

# Trích xuất dữ liệu với đúng các key của thuật toán RSA 
for group in data.get('testGroups', []):
    priv = group['privateKey']
    
    for test in group['tests']:
        if len(output_vectors) >= 35: 
            break
            
        output_vectors.append({
            "tcId": test['tcId'],
            "n": priv['modulus'],
            "e": priv['publicExponent'],
            "d": priv['privateExponent'],
            "msg": test['msg'],
            "label": test.get('label', ''),
            "ct": test['ct'],
            "result": test['result'] 
        })
    if len(output_vectors) >= 35:
        break

with open("vectors.json", "w") as f:
    json.dump(output_vectors, f, indent=4)

print(f"[*] Đã xuất thành công {len(output_vectors)} testcases ra file 'vectors.json'!")