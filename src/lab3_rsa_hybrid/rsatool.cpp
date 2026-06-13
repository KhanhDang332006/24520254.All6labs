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

#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <chrono>
#include <map>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <vector>
#include <set>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace CryptoPP;

// ---------------------------------------------------------
// MACROS FOR DLL/SO EXPORT (CROSS-PLATFORM)
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
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define RSATOOL_API extern "C" __attribute__((visibility("default")))
  #else
    #define RSATOOL_API extern "C"
  #endif
#endif

// =========================================================
// C API ERROR CODES
// =========================================================
#define RSATOOL_SUCCESS 0
#define RSATOOL_ERR_NULL_PTR -1
#define RSATOOL_ERR_INVALID_PARAM -2
#define RSATOOL_ERR_EXCEPTION -3

namespace {

// =========================================================
// BỘ PARSE KEY VÀ UTILS CHUẨN CỦA GIẢNG VIÊN
// =========================================================
enum class KeyMaterialType { UNKNOWN, PUBLIC_KEY, PRIVATE_KEY };
enum class KeyOutputFormat { PEM, DER, BOTH };
enum class OutputFormat { BINARY, HEX, BASE64 };
enum class InputMode { TEXT, FILE };

std::string HexEncode(const std::string& data) {
    std::string encoded;
    StringSource ss(data, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

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
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { 
        return static_cast<char>(std::tolower(c));
     });
    return s;
}

bool ParseOutputFormat(const std::string& s, OutputFormat& fmt) {
    const std::string v = ToLower(s);
    if (v == "binary" || v == "bin" || v == "raw") { 
        fmt = OutputFormat::BINARY; 
        return true; 
    }
    if (v == "hex") { 
        fmt = OutputFormat::HEX; 
        return true; 
    }
    if (v == "text" || v == "base64" || v == "b64") { 
        fmt = OutputFormat::BASE64; 
        return true; 
    }
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

std::string GetBasePrefix(const std::string& path) {
    size_t dotPos = path.find_last_of('.');
    size_t sepPos = path.find_last_of("/\\"); 
    if (dotPos != std::string::npos && (sepPos == std::string::npos || dotPos > sepPos)) {
        return path.substr(0, dotPos); 
    }
    return path;
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

bool ParseEncodeFormat(const std::string& s, OutputFormat& fmt) {
    const std::string v = ToLower(s);
    if (v == "binary" || v == "bin" || v == "raw") { 
        fmt = OutputFormat::BINARY; 
        return true; 
    }
    if (v == "hex") { 
        fmt = OutputFormat::HEX; 
        return true; 
    }
    if (v == "base64" || v == "b64") { 
        fmt = OutputFormat::BASE64; 
        return true; 
    }
    return false;
}

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

std::map<std::string, std::string> JsonEnvelopeParse(const std::string& jsonStr) {
    std::map<std::string, std::string> result;
    size_t pos = 0;

    while ((pos = jsonStr.find('"', pos)) != std::string::npos) {
        size_t keyStart = pos + 1;
        size_t keyEnd = jsonStr.find('"', keyStart);
        if (keyEnd == std::string::npos) throw std::runtime_error("Malformed JSON key");
        
        std::string key = jsonStr.substr(keyStart, keyEnd - keyStart);
        
        pos = jsonStr.find(':', keyEnd + 1);
        if (pos == std::string::npos) throw std::runtime_error("Missing colon for key '" + key + "'");
        
        pos++;
        while (pos < jsonStr.length() && std::isspace(jsonStr[pos])) pos++;
        if (pos >= jsonStr.length()) throw std::runtime_error("Missing value for key '" + key + "'");

        if (jsonStr[pos] == '"') {
            size_t valStart = pos + 1;
            size_t valEnd = jsonStr.find('"', valStart);
            if (valEnd == std::string::npos) throw std::runtime_error("Unterminated string for key '" + key + "'");
            result[key] = jsonStr.substr(valStart, valEnd - valStart);
            pos = valEnd + 1;
        } else {
            size_t valStart = pos;
            while (pos < jsonStr.length() && jsonStr[pos] != ',' && jsonStr[pos] != '}' && !std::isspace(jsonStr[pos])) {
                pos++;
            }
            result[key] = jsonStr.substr(valStart, pos - valStart);
        }
    }
    return result;
}

std::string JsonEnvelopeStringify(const std::vector<std::pair<std::string, std::string>>& data, const std::vector<std::string>& numericKeys) {
    std::string json = "{\n";
    bool first = true;
    for (const auto& pair : data) {
        if (!first) json += ",\n";
        json += "  \"" + pair.first + "\": ";
        if (std::find(numericKeys.begin(), numericKeys.end(), pair.first) != numericKeys.end()) {
            json += pair.second; // In số không có ngoặc kép
        } else {
            json += "\"" + pair.second + "\""; // In chuỗi có ngoặc kép
        }
        first = false;
    }
    json += "\n}";
    return json;
}

// =========================================================
// LOGIC XỬ LÝ CHÍNH
// =========================================================
class RSA_App {
public:

    static void KeyGen(uint32_t bits, const std::string& pubFile, const std::string& privFile) {
        if (bits != 3072 && bits != 4096) {
            throw std::invalid_argument("Invalid RSA Modulus size. Standards strictly require 3072 or 4096 bits.");
        }

        // --- MỚI: Tự động chuẩn hóa tên file thành prefix ---
        std::string pubBase = GetBasePrefix(pubFile);
        std::string privBase = GetBasePrefix(privFile);

        AutoSeededRandomPool rng;
        InvertibleRSAFunction params;
        params.Initialize(rng, bits, Integer(65537)); 

        RSA::PrivateKey privateKey(params);
        RSA::PublicKey publicKey(params);

        if (!privateKey.Validate(rng, 3) || !publicKey.Validate(rng, 3))
            throw std::runtime_error("Key validation failed");

        ByteQueue privQ, pubQ;
        privateKey.Save(privQ);
        publicKey.Save(pubQ);

        std::string privDerBytes = QueueToString(privQ);
        std::string pubDerBytes = QueueToString(pubQ);

        try {
            // Sử dụng pubBase và privBase thay cho pubFile/privFile
            WriteFileBinary(privBase + ".der", privDerBytes);
            WriteFileBinary(pubBase + ".der", pubDerBytes);

            WriteFileBinary(privBase + ".pem", DERToPEM(privDerBytes, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"));
            WriteFileBinary(pubBase + ".pem", DERToPEM(pubDerBytes, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"));

            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            struct tm timeinfo;
            #ifdef _WIN32
                localtime_s(&timeinfo, &now_c);
            #else
                localtime_r(&now_c, &timeinfo);
            #endif
            
            char timeBuf[64];
            std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &timeinfo);

            std::string meta = "{\n";
            meta += "  \"creation_time\": \"" + std::string(timeBuf) + "\",\n";
            meta += "  \"modulus_bits\": " + std::to_string(bits) + ",\n";
            meta += "  \"hash\": \"SHA-256\"\n";
            meta += "}\n";

            WriteFileBinary(pubBase + "_metadata.json", meta);

            if (!privDerBytes.empty()) {
                CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&privDerBytes[0]), privDerBytes.size());
            }
        } catch (...) {
            if (!privDerBytes.empty()) {
                CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&privDerBytes[0]), privDerBytes.size());
            }
            throw;
        }
    }

    static std::string LoadInput(InputMode inputMode, const std::string& inputValue) {
        if (inputMode == InputMode::FILE) return ReadFileBinary(inputValue);
        return inputValue;
    }

    static void EncryptData(InputMode inMode, const std::string& inValue, const std::string& keyPath, const std::string& outFile, OutputFormat outFormat, const std::string& label) {
        AutoSeededRandomPool rng;
        RSA::PublicKey pubKey;
        try {
            pubKey = LoadEncryptionKeyFromFile(keyPath);
        } catch (...) {
            throw std::runtime_error("Cryptographic operation failed: Integrity check or wrong key.");
        }

        std::string plaintext = LoadInput(inMode, inValue);
        std::string finalOutput;
        
        try {
            RSAES_OAEP_SHA256_Encryptor rsaEncryptor(pubKey);
            
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

                std::vector<std::pair<std::string, std::string>> header_data = {
                    {"mode", "RSA-OAEP-AES-GCM"},
                    {"rsa_modulus", std::to_string(pubKey.GetModulus().BitCount())},
                    {"hash", "SHA-256"},
                    {"wrapped_key", Base64Encode(wrappedKey)},
                    {"iv", Base64Encode(std::string(reinterpret_cast<const char*>(iv.data()), iv.size()))},
                    {"tag", Base64Encode(macTag)}
                };

                std::vector<std::string> numericKeys = {"rsa_modulus"};
                std::string jsonHeader = JsonEnvelopeStringify(header_data, numericKeys) + "\n--PAYLOAD--\n";
                finalOutput = jsonHeader + actualCt;
            }

            if (outFormat == OutputFormat::BASE64) finalOutput = Base64Encode(finalOutput);
            else if (outFormat == OutputFormat::HEX) finalOutput = HexEncode(finalOutput);
            
            if (outFile.empty()) {
                std::cout << finalOutput << "\n";
            } else {
                WriteFileBinary(outFile, finalOutput);
            }

            if (!plaintext.empty()) CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&plaintext[0]), plaintext.size());
        } catch (...) {
            if (!plaintext.empty()) CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&plaintext[0]), plaintext.size());
            throw std::runtime_error("Cryptographic operation failed: Integrity check or wrong key.");
        }
    }

    static void DecryptData(InputMode inMode, const std::string& inValue, const std::string& keyPath, const std::string& outFile, OutputFormat inFormat, const std::string& label) {
        AutoSeededRandomPool rng;
        RSA::PrivateKey privKey;
        try {
            privKey = LoadDecryptionKeyFromFile(keyPath);
        } catch (...) {
            throw std::runtime_error("File not found");
        }

        std::string ciphertext = LoadInput(inMode, inValue);
        if (inFormat == OutputFormat::BASE64) ciphertext = Base64Decode(ciphertext);
        else if (inFormat == OutputFormat::HEX) ciphertext = HexDecode(ciphertext);

        std::string aesKey;
        std::string recovered;

        try {
            size_t payloadPos = ciphertext.find("--PAYLOAD--\n");
            if (payloadPos != std::string::npos) {
                std::string header = ciphertext.substr(0, payloadPos);
                std::string actualCt = ciphertext.substr(payloadPos + 12);
                
                std::map<std::string, std::string> j = JsonEnvelopeParse(header); 

                if (j.find("mode") == j.end() || j["mode"] != "RSA-OAEP-AES-GCM" || 
                    j.find("hash") == j.end() || j["hash"] != "SHA-256") {
                    throw std::runtime_error("Cryptographic operation failed: Integrity check or wrong key.");
                }

                std::string wrappedKey = Base64Decode(j["wrapped_key"]);
                std::string iv = Base64Decode(j["iv"]);
                std::string tag = Base64Decode(j["tag"]);

                RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privKey);
                StringSource(wrappedKey, true, new PK_DecryptorFilter(rng, rsaDecryptor, new StringSink(aesKey)));

                GCM<AES>::Decryption gcm;
                gcm.SetKeyWithIV(reinterpret_cast<const byte*>(aesKey.data()), aesKey.size(), reinterpret_cast<const byte*>(iv.data()), iv.size());
                if (!label.empty()) {
                    gcm.SpecifyDataLengths(label.size(), actualCt.size(), 0);
                    gcm.Update(reinterpret_cast<const byte*>(label.data()), label.size());
                }

                AuthenticatedDecryptionFilter df(gcm, new StringSink(recovered));
                df.Put(reinterpret_cast<const byte*>(actualCt.data()), actualCt.size());
                df.Put(reinterpret_cast<const byte*>(tag.data()), tag.size());
                df.MessageEnd(); 
            } else {
                RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privKey);
                recovered.resize(rsaDecryptor.MaxPlaintextLength(ciphertext.length()));
                DecodingResult result = rsaDecryptor.Decrypt(rng, 
                    reinterpret_cast<const byte*>(ciphertext.data()), ciphertext.length(),
                    reinterpret_cast<byte*>(&recovered[0]),
                    MakeParameters(Name::EncodingParameters(), ConstByteArrayParameter(reinterpret_cast<const byte*>(label.data()), label.size()))
                );
                if (!result.isValidCoding) throw std::runtime_error("invalid coding");
                recovered.resize(result.messageLength); 
            }

            if (outFile.empty()) {
                std::cout << (inFormat == OutputFormat::BINARY ? HexEncode(recovered) : recovered) << "\n";
            } else {
                WriteFileBinary(outFile, recovered);
            }

            if (!aesKey.empty()) CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&aesKey[0]), aesKey.size());
            if (!recovered.empty()) CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&recovered[0]), recovered.size());

        } catch (...) {
            if (!aesKey.empty()) CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&aesKey[0]), aesKey.size());
            if (!recovered.empty()) CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&recovered[0]), recovered.size());
            throw std::runtime_error("Cryptographic operation failed: Integrity check or wrong key.");
        }
    }

    static void RunKAT(const std::string& katFile) {
        std::string json = ReadFileBinary(katFile);
        std::cout << "[*] Running Known Answer Tests from: " << katFile << "\n";
        
        size_t pos = 0;
        int passed = 0, failed = 0, total = 0;

        AutoSeededRandomPool rng;

        while ((pos = json.find("\"tcId\"", pos)) != std::string::npos) {
            total++;
            size_t currentTcPos = pos; 
            pos += 6; 
            
            auto extractString = [&](const std::string& key, size_t startPos) -> std::string {
                std::string searchKey = "\"" + key + "\"";
                size_t keyPos = json.find(searchKey, startPos);
                if (keyPos == std::string::npos) return "";
                
                size_t colonPos = json.find(":", keyPos + searchKey.length());
                if (colonPos == std::string::npos) return "";

                size_t valStart = json.find("\"", colonPos);
                if (valStart == std::string::npos) return "";

                size_t valEnd = json.find("\"", valStart + 1);
                if (valEnd == std::string::npos) return "";

                return json.substr(valStart + 1, valEnd - valStart - 1);
            };

            std::string tcIdStr = std::to_string(total);
            size_t idPos = json.find("\"tcId\"", currentTcPos);
            if (idPos != std::string::npos) {
                size_t colonPos = json.find(":", idPos);
                if (colonPos != std::string::npos) {
                    size_t start = colonPos + 1;
                    while (start < json.length() && std::isspace(json[start])) start++;
                    size_t end = start;
                    while (end < json.length() && std::isdigit(json[end])) end++;
                    if (end > start) tcIdStr = json.substr(start, end - start);
                }
            }

            std::string keyPath = extractString("keyPath", currentTcPos);
            std::string msgHex = extractString("msg", currentTcPos);
            std::string ctHex = extractString("ct", currentTcPos);
            std::string labelHex = extractString("label", currentTcPos);
            std::string resultStr = extractString("result", currentTcPos);
            
            if (resultStr.empty() || keyPath.empty()) { continue; }

            std::string expectedMsg = HexDecode(msgHex);
            std::string cipherText = HexDecode(ctHex);
            std::string label = HexDecode(labelHex);
            
            bool testPassed = false;
            std::string errorMsg = "";

            try {
                RSA::PrivateKey privKey = LoadDecryptionKeyFromFile(keyPath);
                RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privKey);
                
                std::string recovered;
                recovered.resize(rsaDecryptor.MaxPlaintextLength(cipherText.length()));
                
                DecodingResult result = rsaDecryptor.Decrypt(rng, 
                    reinterpret_cast<const byte*>(cipherText.data()), cipherText.length(),
                    reinterpret_cast<byte*>(&recovered[0]),
                    MakeParameters(Name::EncodingParameters(), ConstByteArrayParameter(reinterpret_cast<const byte*>(label.data()), label.size()))
                );
                
                if (!result.isValidCoding) {
                    throw std::runtime_error("invalid coding (Padding oracle triggered)");
                }
                recovered.resize(result.messageLength);

                if (resultStr == "valid" || resultStr == "acceptable") {
                    if (recovered == expectedMsg) {
                        testPassed = true;
                    } else {
                        errorMsg = "Plaintext mismatch";
                    }
                } else {
                    errorMsg = "Decryption succeeded but was expected to fail";
                }
                
            } catch (const std::exception& e) {
                if (resultStr == "invalid") {
                    testPassed = true; 
                } else {
                    errorMsg = std::string("Decryption failed: ") + e.what();
                }
            }

            if (testPassed) {
                std::cout << "  [+] Test " << tcIdStr << " (" << resultStr << "): PASS\n";
                passed++;
            } else {
                std::cout << "  [-] Test " << tcIdStr << " (" << resultStr << "): FAIL - " << errorMsg << "\n";
                failed++;
            }
        }
        std::cout << "=========================================================\n";
        std::cout << "KAT Summary: " << passed << "/" << total << " passed. Failed: " << failed << "\n";
    }
};

} // namespace

// =========================================================
// EXPORT C-API VÀ MAIN CLI
// =========================================================

RSATOOL_API int rsatool_keygen(uint32_t bits, const char* pub_file, const char* priv_file, char* err_msg, uint32_t err_size) {
    try {
        if (!pub_file || !priv_file) throw std::invalid_argument("Public and Private key prefixes cannot be null");
        
        // Gọi thẳng hàm KeyGen mới (đã ép cứng xuất cả PEM và DER)
        RSA_App::KeyGen(bits, pub_file, priv_file);
        
        WriteError(err_msg, err_size, "");
        return RSATOOL_SUCCESS;
    } catch (const std::exception& e) {
        WriteError(err_msg, err_size, e.what());
        return RSATOOL_ERR_EXCEPTION;
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
        return RSATOOL_ERR_EXCEPTION;
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
        return RSATOOL_ERR_EXCEPTION;
    }
}

// ============================================================================
// COMMAND LINE INTERFACE & KAT RUNNER (UNIFIED ARCHITECTURE)
// ============================================================================
#ifndef RSATOOL_NO_MAIN

// --- 1. ĐỒNG NHẤT CẤU TRÚC CONFIG (Dành riêng cho Lab 3 - RSA) ---
// (Đặt ngay đây vì chỉ có CLI và main sử dụng)
struct CryptoConfig {
    bool isEncrypt;
    std::string keyPath;
    InputMode inMode;
    std::string inValue;
    std::string outFile;
    OutputFormat outFormat;
    std::string label;
    bool isVerbose = false;
};

void PrintUsage(const char* prog) {
    std::cerr
        << "Usage:\n"
        << "  " << prog << " keygen --bits <3072|4096> --pub <pub_file_prefix> --priv <priv_file_prefix>\n"
        << "  " << prog << " encrypt (--in <file> | --text <string>) --pub <pub.pem> [--out <file>] [--encode raw|hex|base64] [--label <text>]\n"
        << "  " << prog << " decrypt (--in <file> | --text <string>) --priv <priv.pem> [--out <file>] [--encode raw|hex|base64] [--label <text>]\n"
        << "  " << prog << " --kat <path/to/vectors.json>\n"
        << "Run '" << prog << " --help' for more information.\n";
}

void PrintHelp(const char* prog) {
    std::cerr << "=========================================================\n";
    std::cerr << "       RSATOOL - Hybrid RSA-OAEP / AES-GCM Tool          \n";
    std::cerr << "=========================================================\n\n";
    PrintUsage(prog);
    std::cerr
        << "\nOptions:\n"
        << "  --pub <path>       Public Key path (Required for Encrypt / Prefix for Keygen).\n"
        << "  --priv <path>      Private Key path (Required for Decrypt / Prefix for Keygen).\n"
        << "  --in <path>        Input file (binary-safe).\n"
        << "  --text <string>    Input text string (UTF-8).\n"
        << "  --out <path>       Output file (Optional. Prints to screen if omitted).\n"
        << "  --encode <fmt>     Encoding format: raw | hex | base64.\n"
        << "                     (File default: raw. Screen default: hex).\n"
        << "  --label <text>     Optional OAEP label.\n"
        << "  --kat <path>       Run Known Answer Tests from JSON.\n"
        << "  --verbose          Enable detailed execution logs.\n"
        << "=========================================================\n";
}

// --- 2. ĐỒNG NHẤT CLI PARSER (Bảo vệ đầu vào) ---
class CliParser {
public:
    static CryptoConfig Parse(int argc, char* argv[], const std::string& command) {
        CryptoConfig cfg;
        cfg.isEncrypt = (command == "encrypt");
        std::map<std::string, std::string> args;
        std::set<std::string> flags;

        // Quét tham số Fail-Closed
        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--verbose") { flags.insert(arg); continue; }
            if (arg.substr(0, 2) == "--") {
                if (i + 1 >= argc || argv[i+1][0] == '-') throw std::invalid_argument("Fail Closed: Missing value for " + arg);
                if (args.count(arg)) throw std::invalid_argument("Fail Closed: Duplicate argument " + arg);
                args[arg] = argv[++i];
            } else { throw std::invalid_argument("Fail Closed: Unknown positional argument " + arg); }
        }

        cfg.isVerbose = flags.count("--verbose");

        // Validate logic Key
        if (cfg.isEncrypt) {
            if (!args.count("--pub")) throw std::invalid_argument("Fail Closed: Encryption requires --pub parameter.");
            cfg.keyPath = args["--pub"];
        } else {
            if (!args.count("--priv")) throw std::invalid_argument("Fail Closed: Decryption requires --priv parameter.");
            cfg.keyPath = args["--priv"];
        }

        // Validate Input
        bool hasIn = args.count("--in");
        bool hasText = args.count("--text");
        if (hasIn == hasText) throw std::invalid_argument("Fail Closed: Specify exactly one input mode: --in OR --text.");
        
        cfg.inMode = hasText ? InputMode::TEXT : InputMode::FILE;
        cfg.inValue = hasText ? args["--text"] : args["--in"];
        cfg.outFile = args.count("--out") ? args["--out"] : "";
        cfg.label = args.count("--label") ? args["--label"] : "";

        // Quy tắc Encoding PDF
        cfg.outFormat = cfg.outFile.empty() ? OutputFormat::HEX : OutputFormat::BINARY;
        if (args.count("--encode") && !ParseEncodeFormat(args["--encode"], cfg.outFormat)) {
            throw std::invalid_argument("Fail Closed: Invalid --encode value. Use raw, hex, or base64.");
        }

        return cfg;
    }
};

// --- 3. HÀM MAIN SẠCH SẼ VÀ CỨNG CÁP ---
int main(int argc, char* argv[]) {
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    #endif

    if (argc < 2) { PrintUsage(argv[0]); return 1; }
    std::string command = argv[1];
    
    if (command == "--help" || command == "-h") { PrintHelp(argv[0]); return 0; }

    if (command == "--kat") {
        if (argc < 3) {
            std::cerr << "[!] Fail Closed: Missing path for --kat. Example: --kat vectors.json\n";
            return 1;
        }
        try {
            RSA_App::RunKAT(argv[2]); // Tái sử dụng hàm KAT có sẵn của Lab 3
        } catch (const std::exception& e) {
            std::cerr << "[!] CRITICAL ERROR (KAT): " << e.what() << "\n";
            return 1;
        }
        return 0;
    }

    try {
        if (command == "keygen") {
            uint32_t bits = 3072;
            std::string pubFile, privFile;
            for (int i = 2; i < argc; i++) {
                std::string arg = argv[i];
                if (arg == "--bits" && i + 1 < argc) bits = std::stoul(argv[++i]);
                else if (arg == "--pub" && i + 1 < argc) pubFile = argv[++i];
                else if (arg == "--priv" && i + 1 < argc) privFile = argv[++i];
            }
            
            if (pubFile.empty() || privFile.empty()) {
                throw std::invalid_argument("Fail Closed: Missing --pub or --priv parameters.");
            }
            
            RSA_App::KeyGen(bits, pubFile, privFile);
            std::cout << "[+] Keygen successful. Modulus: " << bits << "-bit.\n";
            return 0;
        } 
        else if (command == "encrypt" || command == "decrypt") {
            
            // Cổng Gatekeeper
            CryptoConfig cfg = CliParser::Parse(argc, argv, command);

            if (cfg.isVerbose) std::cout << "[INFO] Target key file: " << cfg.keyPath << "\n";

            // Gọi Core Logic
            if (cfg.isEncrypt) {
                RSA_App::EncryptData(cfg.inMode, cfg.inValue, cfg.keyPath, cfg.outFile, cfg.outFormat, cfg.label);
            } else {
                RSA_App::DecryptData(cfg.inMode, cfg.inValue, cfg.keyPath, cfg.outFile, cfg.outFormat, cfg.label);
            }
            
            if (!cfg.outFile.empty()) {
                std::cout << "[+] " << (cfg.isEncrypt ? "Encryption" : "Decryption") << " successful.\n";
                std::cout << "    Output saved to: " << cfg.outFile << "\n";
            }
            return 0;
        } 
        else {
            std::cerr << "Unknown command: " << command << "\n";
            PrintUsage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] CRITICAL ERROR: " << e.what() << "\n";
        return 1;
    }
}
#endif

