import urllib.request
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Đúng cái link chuẩn v1 của mày
RSA_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/rsa_oaep_3072_sha256_mgf1sha256_test.json"

def int_from_hex(hex_str):
    if not hex_str: return 0
    return int(hex_str, 16)

def main():
    print("[*] Đang tải test vectors RSA-OAEP từ C2SP Wycheproof v1...")
    
    req = urllib.request.Request(RSA_URL, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"[!] Lỗi khi tải dữ liệu: {e}")
        return

    output_tests = []
    key_id = 0
    os.makedirs("kat_data", exist_ok=True)

    for group in data['testGroups']:
        current_keysize = group.get('keysize') or group.get('keySize')
        
        # Lọc đúng RSA-3072 và SHA-256
        if current_keysize == 3072 and group.get('sha') == "SHA-256":
            priv_data = group['privateKey']
            
            # Bắt cả định dạng cũ (n, e, d) và định dạng v1 mới (modulus, publicExponent...)
            n = int_from_hex(priv_data.get('n') or priv_data.get('modulus'))
            e = int_from_hex(priv_data.get('e') or priv_data.get('publicExponent'))
            d = int_from_hex(priv_data.get('d') or priv_data.get('privateExponent'))
            
            p = int_from_hex(priv_data.get('p') or priv_data.get('prime1'))
            q = int_from_hex(priv_data.get('q') or priv_data.get('prime2'))
            
            dp = int_from_hex(priv_data.get('dp') or priv_data.get('exponent1'))
            dq = int_from_hex(priv_data.get('dq') or priv_data.get('exponent2'))
            inv = int_from_hex(priv_data.get('inv') or priv_data.get('coefficient'))
            
            # Dựng lại khóa RSA
            pn = rsa.RSAPrivateNumbers(
                p=p,
                q=q,
                d=d,
                dmp1=dp,
                dmq1=dq,
                iqmp=inv,
                public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
            )
            priv_key = pn.private_key()
            
            # Xuất ra file PEM
            pem_path = f"kat_data/test_key_{key_id}.pem"
            with open(pem_path, "wb") as f:
                f.write(priv_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Ghi nhận test cases
            for test in group['tests']:
                output_tests.append({
                    "tcId": test['tcId'],
                    "keyPath": pem_path,
                    "msg": test['msg'],
                    "ct": test['ct'],
                    "label": test['label'],
                    "result": test['result']
                })
            key_id += 1

    with open("kat_data/vectors.json", "w") as f:
        json.dump(output_tests, f, indent=2)

    print(f"[+] Đã parse thành công {len(output_tests)} test cases vào thư mục kat_data/")

if __name__ == "__main__":
    main()