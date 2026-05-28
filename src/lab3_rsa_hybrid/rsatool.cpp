#ifdef _WIN32
  #define NOMINMAX        // Ngăn windows.h xung đột với hàm min/max chuẩn của C++
  #include <windows.h>
#endif

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/queue.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/hex.h>

#include "json.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <chrono>
#include <map>
#include <cstring>
#include <algorithm>
#include <cctype>

using namespace CryptoPP;
using json =nlohmann::json;

// ---------------------------------------------------------
// 1. MACROS ĐỂ EXPORT THƯ VIỆN (DLL/SO)
// ---------------------------------------------------------
#ifdef _WIN32
  #ifdef RSATOOL_BUILD_DLL
    #define RSATOOL_API extern "C" __declspec(dllexport)
  #elif defined(RSATOOL_USE_DLL)
    #define RSATOOL_API extern "C" __declspec(dllimport)
  #else
    #define RSATOOL_API extern "C"
  #endif
#else
  #define RSATOOL_API extern "C"
#endif

#define RSATOOL_SUCCESS 0
#define RSATOOL_ERROR   1

namespace {

// =========================================================
// BỘ PARSE KEY VÀ UTILS CHUẨN CỦA GIẢNG VIÊN
// =========================================================
enum class KeyMaterialType { UNKNOWN, PUBLIC_KEY, PRIVATE_KEY };
enum class KeyOutputFormat { PEM, DER, BOTH };
enum class OutputFormat { BINARY, TEXT };
enum class InputMode { TEXT, FILE };

std::string HexDecode(const std::string& hex) {
    std::string decoded;
    StringSource ss(hex, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}

void WriteError(char* buffer, uint32_t bufferSize, const std::string& msg) {
    if (!buffer || bufferSize == 0) return;
    const size_t maxCopy = static_cast<size_t>(bufferSize - 1);
    const size_t copyLen = (msg.size() < maxCopy) ? msg.size() : maxCopy;
    std::memcpy(buffer, msg.data(), copyLen);
    buffer[copyLen] = '\0';
}

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool ParseOutputFormat(const std::string& s, OutputFormat& fmt) {
    const std::string v = ToLower(s);
    if (v == "binary" || v == "bin" || v == "raw") { fmt = OutputFormat::BINARY; return true; }
    if (v == "text" || v == "base64" || v == "b64") { fmt = OutputFormat::TEXT; return true; }
    return false;
}

bool ParseKeyFormat(const std::string& s, KeyOutputFormat& fmt) {
    const std::string v = ToLower(s);
    if (v == "pem") { fmt = KeyOutputFormat::PEM; return true; }
    if (v == "der") { fmt = KeyOutputFormat::DER; return true; }
    if (v == "both") { fmt = KeyOutputFormat::BOTH; return true; }
    return false;
}

std::string Base64Encode(const std::string& data) {
    std::string encoded;
    StringSource ss(data, true, new Base64Encoder(new StringSink(encoded), false));
    return encoded;
}

std::string Base64Decode(const std::string& text) {
    std::string decoded;
    StringSource ss(text, true, new Base64Decoder(new StringSink(decoded)));
    return decoded;
}

std::string ReadFileBinary(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open file for reading: " + filename);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void WriteFileBinary(const std::string& filename, const std::string& content) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to open file for writing: " + filename);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) throw std::runtime_error("Failed to write file: " + filename);
}

bool ContainsPEMMarker(const std::string& content) {
    return content.find("-----BEGIN ") != std::string::npos;
}

struct PEMBlock {
    std::string der;
    KeyMaterialType type = KeyMaterialType::UNKNOWN;
};

PEMBlock DecodePEM(const std::string& pemContent) {
    PEMBlock out;
    const size_t beginPos = pemContent.find("-----BEGIN ");
    if (beginPos == std::string::npos) throw std::runtime_error("PEM begin marker not found");

    const size_t beginEnd = pemContent.find("-----", beginPos + 11);
    if (beginEnd == std::string::npos) throw std::runtime_error("Malformed PEM header");

    const std::string headerType = pemContent.substr(beginPos + 11, beginEnd - (beginPos + 11));
    const std::string endMarker = "-----END " + headerType + "-----";
    const size_t endPos = pemContent.find(endMarker, beginEnd + 5);
    if (endPos == std::string::npos) throw std::runtime_error("Matching PEM end marker not found");

    std::string base64;
    for (size_t i = beginEnd + 5; i < endPos; ++i) {
        const unsigned char ch = static_cast<unsigned char>(pemContent[i]);
        if (!std::isspace(ch)) base64.push_back(static_cast<char>(ch));
    }

    if (base64.empty()) throw std::runtime_error("PEM payload is empty");

    const std::string typeLower = ToLower(headerType);
    if (typeLower == "public key" || typeLower == "rsa public key") {
        out.type = KeyMaterialType::PUBLIC_KEY;
    } else if (typeLower == "private key" || typeLower == "rsa private key") {
        out.type = KeyMaterialType::PRIVATE_KEY;
    } else if (typeLower == "encrypted private key") {
        throw std::runtime_error("Encrypted private key PEM is not supported");
    } else {
        out.type = KeyMaterialType::UNKNOWN;
    }

    out.der = Base64Decode(base64);
    return out;
}

void FillQueue(const std::string& bytes, ByteQueue& q) {
    q.Put(reinterpret_cast<const byte*>(bytes.data()), bytes.size());
    q.MessageEnd();
}

bool TryLoadPublicKeyDER(const std::string& derBytes, RSA::PublicKey& publicKey) {
    try { ByteQueue q; FillQueue(derBytes, q); publicKey.BERDecode(q); return true; } catch (...) {}
    try { ByteQueue q; FillQueue(derBytes, q); publicKey.BERDecodePublicKey(q, false, static_cast<CryptoPP::word32>(q.MaxRetrievable())); return true; } catch (...) {}
    try { ByteQueue q; FillQueue(derBytes, q); publicKey.Load(q); return true; } catch (...) {}
    return false;
}

bool TryLoadPrivateKeyDER(const std::string& derBytes, RSA::PrivateKey& privateKey) {
    try { ByteQueue q; FillQueue(derBytes, q); privateKey.BERDecode(q); return true; } catch (...) {}
    try { ByteQueue q; FillQueue(derBytes, q); privateKey.BERDecodePrivateKey(q, false, static_cast<CryptoPP::word32>(q.MaxRetrievable())); return true; } catch (...) {}
    try { ByteQueue q; FillQueue(derBytes, q); privateKey.Load(q); return true; } catch (...) {}
    return false;
}

RSA::PublicKey LoadEncryptionKeyFromFile(const std::string& keyPath) {
    const std::string fileBytes = ReadFileBinary(keyPath);
    std::string derBytes = fileBytes;
    KeyMaterialType hintedType = KeyMaterialType::UNKNOWN;

    if (ContainsPEMMarker(fileBytes)) {
        PEMBlock pem = DecodePEM(fileBytes);
        derBytes = pem.der;
        hintedType = pem.type;
    }

    AutoSeededRandomPool rng;
    if (hintedType == KeyMaterialType::PUBLIC_KEY || hintedType == KeyMaterialType::UNKNOWN) {
        RSA::PublicKey pub;
        if (TryLoadPublicKeyDER(derBytes, pub) && pub.Validate(rng, 3)) return pub;
    }
    if (hintedType == KeyMaterialType::PRIVATE_KEY || hintedType == KeyMaterialType::UNKNOWN) {
        RSA::PrivateKey priv;
        if (TryLoadPrivateKeyDER(derBytes, priv) && priv.Validate(rng, 3)) {
            RSA::PublicKey pub;
            pub.Initialize(priv.GetModulus(), priv.GetPublicExponent());
            if (!pub.Validate(rng, 3)) throw std::runtime_error("Derived public key validation failed");
            return pub;
        }
    }
    throw std::runtime_error("Failed to load RSA public key from file: " + keyPath);
}

RSA::PrivateKey LoadDecryptionKeyFromFile(const std::string& keyPath) {
    const std::string fileBytes = ReadFileBinary(keyPath);
    std::string derBytes = fileBytes;
    KeyMaterialType hintedType = KeyMaterialType::UNKNOWN;

    if (ContainsPEMMarker(fileBytes)) {
        PEMBlock pem = DecodePEM(fileBytes);
        derBytes = pem.der;
        hintedType = pem.type;
    }

    AutoSeededRandomPool rng;
    if (hintedType == KeyMaterialType::PRIVATE_KEY || hintedType == KeyMaterialType::UNKNOWN) {
        RSA::PrivateKey priv;
        if (TryLoadPrivateKeyDER(derBytes, priv) && priv.Validate(rng, 3)) return priv;
    }
    throw std::runtime_error("Failed to load RSA private key from file: " + keyPath);
}

std::string QueueToString(ByteQueue& queue) {
    std::string out;
    out.resize(queue.CurrentSize());
    queue.Get(reinterpret_cast<byte*>(&out[0]), out.size());
    return out;
}

std::string DERToPEM(const std::string& derBytes, const std::string& header, const std::string& footer) {
    std::string base64;
    StringSource ss(reinterpret_cast<const byte*>(derBytes.data()), derBytes.size(), true, 
                    new Base64Encoder(new StringSink(base64), true, 64));
    return header + "\n" + base64 + footer + "\n";
}

// =========================================================
// LOGIC XỬ LÝ CHÍNH
// =========================================================
class RSA_App {
public:

    static void RunKAT(const std::string& katFile) {
        std::ifstream ifs(katFile);
        if (!ifs.is_open()) throw std::runtime_error("Không thể mở file KAT: " + katFile);
        nlohmann::json j;
        ifs >> j;

        int passCount = 0;
        int failCount = 0;

        std::cout << "==================================================\n";
        std::cout << " BẮT ĐẦU CHẠY KNOWN ANSWER TESTS (KAT) - RSA-OAEP \n";
        std::cout << "==================================================\n";

        for (const auto& tc : j) {
            int id = tc["tcId"];
            std::string n_hex = tc["n"];
            std::string e_hex = tc["e"];
            std::string d_hex = tc["d"];
            std::string msg_hex = tc["msg"];
            std::string label_hex = tc.contains("label") ? tc["label"] : "";
            std::string ct_hex = tc["ct"];
            // Wycheproof sử dụng "valid" hoặc "acceptable" cho các test case hợp lệ
            bool expect_valid = (tc["result"] == "valid" || tc["result"] == "acceptable");

            try {
                // Khởi tạo khóa Private Key từ dữ liệu thô (n, e, d)
                std::string n_bin = HexDecode(n_hex);
                std::string e_bin = HexDecode(e_hex);
                std::string d_bin = HexDecode(d_hex);
                
                Integer n(reinterpret_cast<const byte*>(n_bin.data()), n_bin.size());
                Integer e(reinterpret_cast<const byte*>(e_bin.data()), e_bin.size());
                Integer d(reinterpret_cast<const byte*>(d_bin.data()), d_bin.size());

                RSA::PrivateKey priv;
                priv.Initialize(n, e, d);

                // Thiết lập cấu hình OAEP-SHA256
                RSAES_OAEP_SHA256_Decryptor rsaDecryptor(priv);
                std::string ct = HexDecode(ct_hex);
                std::string expected_msg = HexDecode(msg_hex);
                std::string label = HexDecode(label_hex);

                std::string recovered;
                recovered.resize(rsaDecryptor.MaxPlaintextLength(ct.length()));

                AutoSeededRandomPool rng;
                DecodingResult res = rsaDecryptor.Decrypt(rng,
                    reinterpret_cast<const byte*>(ct.data()), ct.length(),
                    reinterpret_cast<byte*>(&recovered[0]),
                    MakeParameters(Name::EncodingParameters(), ConstByteArrayParameter(reinterpret_cast<const byte*>(label.data()), label.size()))
                );

                // Đánh giá kết quả giải mã và đối chiếu Plaintext
                bool is_valid = res.isValidCoding && (expected_msg == recovered.substr(0, res.messageLength));

                if (is_valid == expect_valid) {
                    std::cout << "[PASS] Test Case " << id << "\n";
                    passCount++;
                } else {
                    std::cout << "[FAIL] Test Case " << id << " - Trạng thái không khớp (Expected: " 
                              << (expect_valid ? "Hợp lệ" : "Không hợp lệ") << ")\n";
                    failCount++;
                }
            } catch (const std::exception& ex) {
                if (!expect_valid) {
                    // Nếu test case được thiết kế để gây lỗi (invalid ciphertext/label), bắt được exception là PASS
                    std::cout << "[PASS] Test Case " << id << " (Bắt được lỗi như dự kiến: " << ex.what() << ")\n";
                    passCount++;
                } else {
                    std::cout << "[FAIL] Test Case " << id << " - Lỗi hệ thống: " << ex.what() << "\n";
                    failCount++;
                }
            }
        }

        std::cout << "\n---------------- KAT SUMMARY ----------------\n";
        std::cout << "Tổng số Test Cases : " << (passCount + failCount) << "\n";
        std::cout << "Thành công (PASS)  : " << passCount << "\n";
        std::cout << "Thất bại   (FAIL)  : " << failCount << "\n";
        std::cout << "==================================================\n";
    }

    static void KeyGen(uint32_t bits, const std::string& prefix, KeyOutputFormat format) {
        if (bits != 3072 && bits != 4096) {
            throw std::invalid_argument("Invalid RSA Modulus size. Standards strictly require 3072 or 4096 bits.");
        }

        AutoSeededRandomPool rng;
        InvertibleRSAFunction params;
        params.Initialize(rng, bits, Integer(65537)); // Bắt buộc e = 65537

        RSA::PrivateKey privateKey(params);
        RSA::PublicKey publicKey(params);

        if (!privateKey.Validate(rng, 3) || !publicKey.Validate(rng, 3))
            throw std::runtime_error("Key validation failed");

        ByteQueue privQ, pubQ;
        privateKey.Save(privQ);
        publicKey.Save(pubQ);

        std::string privDerBytes = QueueToString(privQ);
        std::string pubDerBytes = QueueToString(pubQ);

        if (format == KeyOutputFormat::DER || format == KeyOutputFormat::BOTH) {
            WriteFileBinary(prefix + "_private.der", privDerBytes);
            WriteFileBinary(prefix + "_public.der", pubDerBytes);
        }

        if (format == KeyOutputFormat::PEM || format == KeyOutputFormat::BOTH) {
            WriteFileBinary(prefix + "_private.pem", DERToPEM(privDerBytes, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"));
            WriteFileBinary(prefix + "_public.pem", DERToPEM(pubDerBytes, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"));
        }

        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::string meta = "{\n  \"creation_time\": \"" + std::string(std::ctime(&now));
        meta.pop_back(); 
        meta += "\",\n  \"modulus_bits\": " + std::to_string(bits) + ",\n  \"hash\": \"SHA-256\"\n}\n";
        WriteFileBinary(prefix + "_metadata.json", meta);
    }

    static std::string LoadInput(InputMode inputMode, const std::string& inputValue) {
        if (inputMode == InputMode::FILE) return ReadFileBinary(inputValue);
        return inputValue;
    }

    static void EncryptData(InputMode inMode, const std::string& inValue, const std::string& keyPath, const std::string& outFile, OutputFormat outFormat, const std::string& label) {
        AutoSeededRandomPool rng;
        RSA::PublicKey pubKey = LoadEncryptionKeyFromFile(keyPath);
        std::string plaintext = LoadInput(inMode, inValue);
        
        RSAES_OAEP_SHA256_Encryptor rsaEncryptor(pubKey);
        std::string finalOutput;
        
        if (plaintext.length() <= rsaEncryptor.FixedMaxPlaintextLength()) {
            std::string ciphertext;
            ciphertext.resize(rsaEncryptor.CiphertextLength(plaintext.length()));

            rsaEncryptor.Encrypt(rng, 
                reinterpret_cast<const byte*>(plaintext.data()), plaintext.length(),
                reinterpret_cast<byte*>(&ciphertext[0]),
                MakeParameters(Name::EncodingParameters(), ConstByteArrayParameter(reinterpret_cast<const byte*>(label.data()), label.size()))
            );
            finalOutput = ciphertext;
        } else {
            // Hybrid Encryption
            SecByteBlock aesKey(AES::MAX_KEYLENGTH);
            SecByteBlock iv(12);
            rng.GenerateBlock(aesKey, aesKey.size());
            rng.GenerateBlock(iv, iv.size());

            std::string aesCiphertext;
            GCM<AES>::Encryption gcm;
            gcm.SetKeyWithIV(aesKey, aesKey.size(), iv, iv.size());
            if (!label.empty()) {
                gcm.SpecifyDataLengths(label.size(), plaintext.size(), 0);
                gcm.Update(reinterpret_cast<const byte*>(label.data()), label.size());
            }
            StringSource(plaintext, true, new AuthenticatedEncryptionFilter(gcm, new StringSink(aesCiphertext)));
            
            std::string actualCt = aesCiphertext.substr(0, aesCiphertext.length() - 16);
            std::string macTag = aesCiphertext.substr(aesCiphertext.length() - 16);

            std::string wrappedKey;
            StringSource(aesKey.data(), aesKey.size(), true, new PK_EncryptorFilter(rng, rsaEncryptor, new StringSink(wrappedKey)));

            json header_json;
            header_json["mode"] = "RSA-OAEP-AES-GCM";
            header_json["rsa_modulus"] = pubKey.GetModulus().BitCount();
            header_json["hash"] = "SHA-256";
            header_json["wrapped_key"] = Base64Encode(wrappedKey);
            header_json["iv"] = Base64Encode(std::string(reinterpret_cast<const char*>(iv.data()), iv.size()));
            header_json["tag"] = Base64Encode(macTag);


            std::string jsonHeader = header_json.dump(2) + "\n--PAYLOAD--\n";
            finalOutput = jsonHeader + actualCt;
        }

        if (outFormat == OutputFormat::TEXT) {
            finalOutput = Base64Encode(finalOutput);
        }
        WriteFileBinary(outFile, finalOutput);
    }

    static void DecryptData(InputMode inMode, const std::string& inValue, const std::string& keyPath, const std::string& outFile, OutputFormat inFormat, const std::string& label) {
        AutoSeededRandomPool rng;
        RSA::PrivateKey privKey = LoadDecryptionKeyFromFile(keyPath);
        std::string ciphertext = LoadInput(inMode, inValue);

        if (inFormat == OutputFormat::TEXT) {
            ciphertext = Base64Decode(ciphertext);
        }

        size_t payloadPos = ciphertext.find("--PAYLOAD--\n");
        if (payloadPos != std::string::npos) {
            // Hybrid Decryption
            std::string header = ciphertext.substr(0, payloadPos);
            std::string actualCt = ciphertext.substr(payloadPos + 12);

           try {
                // 1. Parse chuỗi thành cấu trúc dữ liệu JSON
                json j = json::parse(header);

                // 2. Validate bảo mật (Sản phẩm chuẩn phải có)
                if (!j.contains("mode") || j["mode"] != "RSA-OAEP-AES-GCM") {
                    throw std::runtime_error("Tampered Header: Unsupported encryption mode");
                }
                if (!j.contains("hash") || j["hash"] != "SHA-256") {
                    throw std::runtime_error("Tampered Header: Mismatched hash algorithm");
                }
                if (!j.contains("wrapped_key") || !j.contains("iv") || !j.contains("tag")) {
                    throw std::runtime_error("Corrupted Header: Missing crypto parameters");
                }

            std::string wrappedKey = Base64Decode(j["wrapped_key"].get<std::string>());
            std::string iv = Base64Decode(j["iv"].get<std::string>());
            std::string tag = Base64Decode(j["tag"].get<std::string>());

            RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privKey);
            std::string aesKey;
            StringSource(wrappedKey, true, new PK_DecryptorFilter(rng, rsaDecryptor, new StringSink(aesKey)));

            GCM<AES>::Decryption gcm;
            gcm.SetKeyWithIV(reinterpret_cast<const byte*>(aesKey.data()), aesKey.size(), reinterpret_cast<const byte*>(iv.data()), iv.size());
            if (!label.empty()) {
                gcm.SpecifyDataLengths(label.size(), actualCt.size(), 0);
                gcm.Update(reinterpret_cast<const byte*>(label.data()), label.size());
            }

            std::string recovered;
            AuthenticatedDecryptionFilter df(gcm, new StringSink(recovered));
            df.Put(reinterpret_cast<const byte*>(actualCt.data()), actualCt.size());
            df.Put(reinterpret_cast<const byte*>(tag.data()), tag.size());
            df.MessageEnd();

            WriteFileBinary(outFile, recovered);

            } catch (const json::parse_error& e) {
        // Bắt lỗi nếu kẻ tấn công phá cú pháp JSON (thiếu dấu phẩy, dấu ngoặc...)
        throw std::runtime_error("Decryption failed: Invalid Envelope Header format.");
    } catch (const json::type_error& e) {
        // Bắt lỗi nếu kẻ tấn công cố tình đổi kiểu dữ liệu (vd truyền số thay vì chuỗi)
        throw std::runtime_error("Decryption failed: Header type mismatch.");
    }
        } else {
            // Direct Decryption 
            RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privKey);
            std::string recovered;
            recovered.resize(rsaDecryptor.MaxPlaintextLength(ciphertext.length()));

            DecodingResult result = rsaDecryptor.Decrypt(rng, 
                reinterpret_cast<const byte*>(ciphertext.data()), ciphertext.length(),
                reinterpret_cast<byte*>(&recovered[0]),
                MakeParameters(Name::EncodingParameters(), ConstByteArrayParameter(reinterpret_cast<const byte*>(label.data()), label.size()))
            );

            if (!result.isValidCoding) {
                throw std::runtime_error("Decryption failed: Label mismatch or corrupted ciphertext!");
            }
            
            recovered.resize(result.messageLength); 
            WriteFileBinary(outFile, recovered);
        }
    }
};

} // namespace

// =========================================================
// EXPORT C-API VÀ MAIN CLI
// =========================================================

RSATOOL_API int rsatool_keygen(uint32_t bits, const char* prefix, const char* format_str, char* err_msg, uint32_t err_size) {
    try {
        if (!prefix || !format_str) throw std::invalid_argument("Prefix and format cannot be null");
        KeyOutputFormat fmt;
        if (!ParseKeyFormat(format_str, fmt)) throw std::invalid_argument("Invalid format. Use pem, der, or both.");
        RSA_App::KeyGen(bits, prefix, fmt);
        WriteError(err_msg, err_size, "");
        return RSATOOL_SUCCESS;
    } catch (const std::exception& e) {
        WriteError(err_msg, err_size, e.what());
        return RSATOOL_ERROR;
    }
}

RSATOOL_API int rsatool_encrypt(const char* in_file, const char* key_path, const char* out_file, const char* label, char* err_msg, uint32_t err_size) {
    try {
        if (!in_file || !key_path || !out_file) throw std::invalid_argument("Paths cannot be null");
        std::string lbl = label ? label : "";
        RSA_App::EncryptData(InputMode::FILE, in_file, key_path, out_file, OutputFormat::BINARY, lbl);
        WriteError(err_msg, err_size, "");
        return RSATOOL_SUCCESS;
    } catch (const std::exception& e) {
        WriteError(err_msg, err_size, std::string("Encryption failed: ") + e.what());
        return RSATOOL_ERROR;
    }
}

RSATOOL_API int rsatool_decrypt(const char* in_file, const char* key_path, const char* out_file, const char* label, char* err_msg, uint32_t err_size) {
    try {
        if (!in_file || !key_path || !out_file) throw std::invalid_argument("Paths cannot be null");
        std::string lbl = label ? label : "";
        RSA_App::DecryptData(InputMode::FILE, in_file, key_path, out_file, OutputFormat::BINARY, lbl);
        WriteError(err_msg, err_size, "");
        return RSATOOL_SUCCESS;
    } catch (const std::exception& e) {
        WriteError(err_msg, err_size, std::string("Decryption failed: ") + e.what());
        return RSATOOL_ERROR;
    }
}

#ifndef RSATOOL_NO_MAIN
void PrintUsage(const char* prog) {
    std::cerr
        << "RSATOOL - Hybrid RSA-OAEP / AES-GCM Tool\n\n"
        << "Usage:\n"
        << "  " << prog << " keygen --bits <3072|4096> --prefix <name> [--format pem|der|both]\n"
        << "  " << prog << " encrypt --key <keyfile> (--in <file> | --text <string>) --out <file> [--out-format binary|text] [--label <text>]\n"
        << "  " << prog << " decrypt --key <keyfile> (--in <file> | --text <string>) --out <file> [--in-format binary|text]  [--label <text>]\n"
        << "  " << prog << " --kat <vectors.json>\n\n"
        << "Options:\n"
        << "  --key <path>       RSA key file in PEM or DER. Automatically handles Public or Private keys.\n"
        << "  --text <string>    Input from command line string.\n"
        << "  --in <path>        Input from file.\n"
        << "  --out <path>       Output file path.\n"
        << "  --format           pem | der | both (For keygen, default: both)\n"
        << "  --out-format       binary | text (For encryption output, default: binary)\n"
        << "  --in-format        binary | text (For decryption input, default: binary)\n"
        << "  --kat <path>       Run Known Answer Tests (KAT) against a Wycheproof JSON file.\n\n"
        << "Examples:\n"
        << "  " << prog << " keygen --bits 3072 --prefix server --format pem\n"
        << "  " << prog << " encrypt --key server_public.pem --text \"Secret payload\" --out cipher.bin --label \"v1\"\n"
        << "  " << prog << " decrypt --key server_private.pem --in cipher.bin --out plain.txt --label \"v1\"\n"
        << "  " << prog << " --kat rsa_oaep_3072_sha256_mgf1sha256_test.json\n";
}

int main(int argc, char* argv[]) {

    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    #endif

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    std::string command = argv[1];
    if (command == "--help" || command == "-h") {
        PrintUsage(argv[0]);
        return 0;
    }

    std::map<std::string, std::string> args;
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg.substr(0, 2) == "--" && i + 1 < argc) {
            args[arg] = argv[++i];
        }
    }

    try {
        if (command == "--kat") {
            if (argc < 3) {
                throw std::invalid_argument("Thiếu đường dẫn đến file vectors.json. Tham số: --kat <file_path>");
            }
            RSA_App::RunKAT(argv[2]);
            return 0;
        }
        else if (command == "keygen") {
            uint32_t bits = args.count("--bits") ? std::stoul(args["--bits"]) : 3072;
            if (!args.count("--prefix")) throw std::invalid_argument("Missing --prefix parameter.");
            
            KeyOutputFormat fmt = KeyOutputFormat::BOTH;
            if (args.count("--format") && !ParseKeyFormat(args["--format"], fmt)) {
                throw std::invalid_argument("Invalid --format value. Use pem, der, or both.");
            }
            
            RSA_App::KeyGen(bits, args["--prefix"], fmt);
            std::cout << "[+] Keygen successful. Prefix: " << args["--prefix"] << "\n";
        } 
        else if (command == "encrypt" || command == "decrypt") {
            bool isEncrypt = (command == "encrypt");
            
            if (!args.count("--key")) throw std::invalid_argument("Missing --key parameter.");
            if (!args.count("--out")) throw std::invalid_argument("Missing --out parameter.");

            bool hasText = args.count("--text");
            bool hasIn = args.count("--in");
            if (hasText == hasIn) {
                throw std::invalid_argument("Specify exactly one of --text or --in.");
            }

            InputMode inMode = hasText ? InputMode::TEXT : InputMode::FILE;
            std::string inValue = hasText ? args["--text"] : args["--in"];
            std::string label = args.count("--label") ? args["--label"] : "";

            OutputFormat fmt = OutputFormat::BINARY;
            std::string fmtArg = isEncrypt ? (args.count("--out-format") ? args["--out-format"] : "") 
                                           : (args.count("--in-format") ? args["--in-format"] : "");
            
            if (!fmtArg.empty() && !ParseOutputFormat(fmtArg, fmt)) {
                throw std::invalid_argument("Invalid format value. Use binary or text.");
            }

            if (isEncrypt) {
                RSA_App::EncryptData(inMode, inValue, args["--key"], args["--out"], fmt, label);
            } else {
                RSA_App::DecryptData(inMode, inValue, args["--key"], args["--out"], fmt, label);
            }
            
            std::cout << "[+] " << (isEncrypt ? "Encryption" : "Decryption") << " successful.\n";
            std::cout << "    Key: " << args["--key"] << "\n";
            std::cout << "    Output: " << args["--out"] << "\n";
        } 
        else {
            std::cerr << "Unknown command: " << command << "\n";
            PrintUsage(argv[0]);
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
}

#endif
