#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/xts.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/sha.h>
#include <cryptopp/channels.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <filesystem>
#include <map>
#include <set>
#include <cctype>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace CryptoPP;
namespace fs = std::filesystem;

// ---------------------------------------------------------
// MACROS FOR DLL/SO EXPORT (CROSS-PLATFORM)
// ---------------------------------------------------------
#ifdef _WIN32
  #ifdef AESTOOL_BUILD_DLL
    #define AESTOOL_API extern "C" __declspec(dllexport)
  #elif defined(AESTOOL_USE_DLL)
    #define AESTOOL_API extern "C" __declspec(dllimport)
  #else
    #define AESTOOL_API extern "C"
  #endif
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define AESTOOL_API extern "C" __attribute__((visibility("default")))
  #else
    #define AESTOOL_API extern "C"
  #endif
#endif

// =========================================================
// C API ERROR CODES
// =========================================================
#define AESTOOL_SUCCESS 0
#define AESTOOL_ERR_NULL_PTR -1
#define AESTOOL_ERR_INVALID_PARAM -2
#define AESTOOL_ERR_EXCEPTION -3

namespace {

// =========================================================
// STANDARD UTILS
// =========================================================
enum class OutputFormat { BINARY, HEX, BASE64 };
enum class InputMode { TEXT, FILE };

struct CryptoConfig {
    bool isEncrypt;
    std::string mode;
    std::string keyRaw;
    InputMode inMode;
    std::string inValue;
    std::string outFile;
    OutputFormat outFormat;
    
    // AEAD & Security Options
    bool isAead = false;
    bool allowEcb = false;
    bool isVerbose = false;
    
    std::string explicitIvRaw;
    std::string aadRaw;
    std::string explicitTagHex;
    int threads = 1;
};

void WriteError(char* buffer, uint32_t bufferSize, const std::string& msg) {
    if (!buffer || bufferSize == 0) return;
    const size_t maxCopy = static_cast<size_t>(bufferSize - 1);
    const size_t copyLen = (msg.size() < maxCopy) ? msg.size() : maxCopy;
    std::memcpy(buffer, msg.data(), copyLen);
    buffer[copyLen] = '\0';
}

std::string HexEncode(const std::string& data) {
    std::string encoded;
    StringSource ss(data, true, new HexEncoder(new StringSink(encoded), true)); // Upper-case
    return encoded;
}

std::string HexDecode(const std::string& hex) {
    std::string decoded;
    StringSource ss(hex, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
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

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool ParseEncodeFormat(const std::string& s, OutputFormat& fmt) {
    const std::string v = ToLower(s);
    if (v == "binary" || v == "bin" || v == "raw") { fmt = OutputFormat::BINARY; return true; }
    if (v == "hex") { fmt = OutputFormat::HEX; return true; }
    if (v == "base64" || v == "b64") { fmt = OutputFormat::BASE64; return true; }
    return false;
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

std::string LoadInput(InputMode inputMode, const std::string& inputValue) {
    if (inputMode == InputMode::FILE) return ReadFileBinary(inputValue);
    return inputValue;
}

bool IsHexString(const std::string& str) {
    if (str.empty()) return false;
    for (char c : str) {
        if (!std::isxdigit(static_cast<unsigned char>(c)) && !std::isspace(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

// =========================================================
// SIDECAR JSON MANAGER & NONCE TRACKER
// =========================================================
struct SidecarMeta {
    std::string alg;
    std::string mode; // Bổ sung biến mode
    std::string iv_hex;
    std::string aad_hex;
    std::string tag_hex;
};

void SaveSidecar(const std::string& file, const SidecarMeta& meta) {
    std::string json = "{\n";
    json += "  \"alg\": \"" + meta.alg + "\",\n";
    json += "  \"mode\": \"" + meta.mode + "\",\n"; // Ghi mode ngay dưới alg
    json += "  \"iv\": \"" + meta.iv_hex + "\"";
    if (!meta.aad_hex.empty()) json += ",\n  \"aad\": \"" + meta.aad_hex + "\"";
    if (!meta.tag_hex.empty()) json += ",\n  \"tag\": \"" + meta.tag_hex + "\"";
    json += "\n}\n";
    WriteFileBinary(file, json);
}

SidecarMeta LoadSidecar(const std::string& file) {
    SidecarMeta meta;
    std::string json;
    try { json = ReadFileBinary(file); } catch (...) { return meta; }

    auto extractJsonVal = [&](const std::string& key) -> std::string {
        size_t keyPos = json.find("\"" + key + "\"");
        if (keyPos == std::string::npos) return "";
        size_t colon = json.find(":", keyPos);
        size_t start = json.find("\"", colon);
        if (start == std::string::npos) return "";
        size_t end = json.find("\"", start + 1);
        if (end == std::string::npos) return "";
        return json.substr(start + 1, end - start - 1);
    };

    meta.alg = extractJsonVal("alg");
    meta.mode = extractJsonVal("mode"); // Đọc thêm mode từ file JSON
    meta.iv_hex = extractJsonVal("iv");
    meta.aad_hex = extractJsonVal("aad");
    meta.tag_hex = extractJsonVal("tag");
    return meta;
}

struct NonceTracker {
    static std::string HashKeyNonce(const std::string& keyBytes, const std::string& nonceBytes) {
        SHA256 hash;
        std::string digest;
        StringSource s(keyBytes + nonceBytes, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
        return digest;
    }

    static void CheckAndRegister(const std::string& mode, const std::string& keyBytes, const std::string& nonceBytes) {
        if (mode != "ctr" && mode != "gcm" && mode != "ccm") return;

        std::string dbPath = ".nonce_db";
        std::string record = HashKeyNonce(keyBytes, nonceBytes);

        if (fs::exists(dbPath)) {
            std::string content = ReadFileBinary(dbPath);
            if (content.find(record) != std::string::npos) {
                throw std::runtime_error("CATASTROPHIC ERROR: Nonce reuse detected! Operation rejected to prevent Keystream Reuse attack.");
            }
        }
        
        std::ofstream out(dbPath, std::ios::app);
        out << record << "\n";
    }
};

// =========================================================
// AES LOGIC CORE
// =========================================================
class AES_App {
public:
    static void GenerateKey(const std::string& outfile, size_t keyLength = AES::MAX_KEYLENGTH) {
        AutoSeededRandomPool prng;
        SecByteBlock key(keyLength);
        prng.GenerateBlock(key, key.size());

        std::string hexKey = HexEncode(std::string(reinterpret_cast<const char*>(key.data()), key.size()));
        WriteFileBinary(outfile, hexKey + "\n");
    }

    template<class ENC_MODE>
    static std::string EncryptStandard(const std::string& pt, const SecByteBlock& key, const SecByteBlock& iv) {
        ENC_MODE enc;
        if (iv.size() > 0) enc.SetKeyWithIV(key, key.size(), iv, iv.size());
        else enc.SetKey(key, key.size());

        std::string ct;
        StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(ct)));
        return ct;
    }

    template<class DEC_MODE>
    static std::string DecryptStandard(const std::string& ct, const SecByteBlock& key, const SecByteBlock& iv) {
        DEC_MODE dec;
        if (iv.size() > 0) dec.SetKeyWithIV(key, key.size(), iv, iv.size());
        else dec.SetKey(key, key.size());

        std::string pt;
        StringSource(ct, true, new StreamTransformationFilter(dec, new StringSink(pt)));
        return pt;
    }

    template<class AEAD_ENC>
    static std::string EncryptAEAD(const std::string& pt, const SecByteBlock& key, const SecByteBlock& iv, const std::string& aad, std::string& outTagHex) {
        AEAD_ENC enc;
        enc.SetKeyWithIV(key, key.size(), iv, iv.size());
        enc.SpecifyDataLengths(aad.size(), pt.size(), 0);

        std::string ct;
        // ĐỒNG BỘ: Dùng constructor mặc định giống KAT. 
        // Crypto++ tự động sinh MAC size tiêu chuẩn (16) cho GCM/CCM.
        AuthenticatedEncryptionFilter ef(enc, new StringSink(ct));

        if (!aad.empty()) {
            ef.ChannelPut(AAD_CHANNEL, reinterpret_cast<const byte*>(aad.data()), aad.size());
            ef.ChannelMessageEnd(AAD_CHANNEL);
        }

        ef.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(pt.data()), pt.size());
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);

        // ct chứa [Ciphertext + MAC]
        std::string final_ct = ct.substr(0, pt.size());
        std::string final_tag = ct.substr(pt.size());

        outTagHex = HexEncode(final_tag);
        return final_ct;
    }

    template<class AEAD_DEC>
    static std::string DecryptAEAD(const std::string& ct, const SecByteBlock& key, const SecByteBlock& iv, const std::string& aad, const std::string& expectedTagHex) {
        AEAD_DEC dec;
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());
        dec.SpecifyDataLengths(aad.size(), ct.size(), 0);

        std::string tag = HexDecode(expectedTagHex);
        std::string pt;
        int tagSize = static_cast<int>(tag.size());
        AuthenticatedDecryptionFilter df(dec, new StringSink(pt), 
            AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION, tagSize);

        if (!aad.empty()) {
            df.ChannelPut(AAD_CHANNEL, reinterpret_cast<const byte*>(aad.data()), aad.size());
            df.ChannelMessageEnd(AAD_CHANNEL);
        }

        df.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(ct.data()), ct.size());
        df.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(tag.data()), tag.size());
        df.ChannelMessageEnd(DEFAULT_CHANNEL);

        return pt;
    }

    static void Process(const CryptoConfig& cfg) {
        // [THÊM ĐOẠN NÀY VÀO ĐẦU HÀM]: Giải nén biến từ struct cfg
        bool isEncrypt = cfg.isEncrypt;
        std::string mode = cfg.mode;
        std::string keyRaw = cfg.keyRaw;
        InputMode inMode = cfg.inMode;
        std::string inValue = cfg.inValue;
        std::string outFile = cfg.outFile;
        OutputFormat outFormat = cfg.outFormat;
        bool allowEcb = cfg.allowEcb;
        bool isVerbose = cfg.isVerbose;
        std::string explicitIvRaw = cfg.explicitIvRaw;
        std::string explicitTagHex = cfg.explicitTagHex;
        std::string actualAad = cfg.aadRaw;
        
        // 1. Validate Mode & Key size for specific modes
        std::set<std::string> validModes = {"ecb", "cbc", "ofb", "cfb", "ctr", "xts", "gcm", "ccm"};
        if (validModes.find(mode) == validModes.end()) {
            throw std::invalid_argument("Unsupported AES mode: " + mode);
        }

        if (mode == "xts" && keyRaw.size() < 32) {
            throw std::invalid_argument("XTS mode requires at least a 256-bit (32-byte) key (split into two 128-bit keys). Current size: " + std::to_string(keyRaw.size()));
        }

        SecByteBlock key(reinterpret_cast<const byte*>(keyRaw.data()), keyRaw.size());
        std::string inputData = LoadInput(inMode, inValue);

        if (isVerbose) {
            std::cout << "[INFO] Mode: " << mode << " | Key Size: " << keyRaw.size() * 8 << " bits | Input Size: " << inputData.size() << " bytes.\n";
        }

        if (mode == "ecb") {
            if (isVerbose) std::cout << "[!] WARNING: ECB mode is highly insecure (Pattern repetition).\n";
            if (inputData.size() > 16384 && !allowEcb) {
                throw std::runtime_error("ECB mode is blocked for payloads larger than 16 KiB. Use --allow-ecb to override.");
            }
        }

        SecByteBlock iv;
        std::string tagHex = explicitTagHex;
        SidecarMeta meta;

        if (isEncrypt) {
            if (mode != "ecb") {
                if (explicitIvRaw.empty()) {
                    // Auto-gen: Khuyến nghị 12 byte cho GCM/CCM, 16 byte cho các mode khác.
                    size_t genIvLen = (mode == "gcm" || mode == "ccm") ? 12 : AES::BLOCKSIZE;
                    iv.CleanNew(genIvLen);
                    AutoSeededRandomPool prng;
                    prng.GenerateBlock(iv, iv.size());
                    if (isVerbose) std::cout << "[INFO] Auto-generated secure random IV/Nonce (" << genIvLen << " bytes).\n";
                } else {
                    size_t ivLen = explicitIvRaw.size();
                    if (mode == "ccm" && (ivLen < 7 || ivLen > 13)) {
                        throw std::invalid_argument("Invalid IV length. CCM mode requires Nonce to be 7-13 bytes.");
                    } else if (mode == "gcm" && ivLen == 0) {
                        throw std::invalid_argument("Invalid IV length. GCM IV cannot be empty.");
                    } else if (mode != "gcm" && mode != "ccm" && ivLen != AES::BLOCKSIZE) {
                        throw std::invalid_argument("Invalid IV length. Expected 16 bytes for block modes.");
                    }
                    iv.Assign(reinterpret_cast<const byte*>(explicitIvRaw.data()), ivLen);
                }
            }
            std::string ivStr(reinterpret_cast<const char*>(iv.data()), iv.size());
            NonceTracker::CheckAndRegister(mode, keyRaw, ivStr);
        } else {
            if (inMode == InputMode::FILE) {
                meta = LoadSidecar(inValue + ".json");
                if (isVerbose && !meta.alg.empty()) std::cout << "[INFO] Sidecar metadata loaded successfully.\n";
            }
            
            std::string ivHexToUse = explicitIvRaw.empty() ? meta.iv_hex : HexEncode(explicitIvRaw);
            if (mode != "ecb") {
                if (ivHexToUse.empty()) throw std::runtime_error("Missing IV/Nonce for decryption.");
                std::string ivDecoded = HexDecode(ivHexToUse);
                size_t ivLen = ivDecoded.size();

                if (mode == "ccm" && (ivLen < 7 || ivLen > 13)) {
                    throw std::invalid_argument("Invalid IV length for decryption. CCM mode requires Nonce to be 7-13 bytes.");
                } else if (mode == "gcm" && ivLen == 0) {
                    throw std::invalid_argument("Invalid IV length for decryption. GCM IV cannot be empty.");
                } else if (mode != "gcm" && mode != "ccm" && ivLen != AES::BLOCKSIZE) {
                    throw std::invalid_argument("Invalid IV length for decryption. Expected 16 bytes for block modes.");
                }
                iv.Assign(reinterpret_cast<const byte*>(ivDecoded.data()), ivLen);
            }

            tagHex = explicitTagHex.empty() ? meta.tag_hex : explicitTagHex;
            if (actualAad.empty() && !meta.aad_hex.empty()) actualAad = HexDecode(meta.aad_hex);

            if ((mode == "gcm" || mode == "ccm") && tagHex.empty()) {
                throw std::invalid_argument("Missing authentication tag! Cannot decrypt AEAD without a tag.");
            }

            if (outFormat == OutputFormat::BASE64) inputData = Base64Decode(inputData);
            else if (outFormat == OutputFormat::HEX) inputData = HexDecode(inputData);
        }

        std::string resultData;
        try {
            if (mode == "ecb") resultData = isEncrypt ? EncryptStandard<ECB_Mode<AES>::Encryption>(inputData, key, iv) : DecryptStandard<ECB_Mode<AES>::Decryption>(inputData, key, iv);
            else if (mode == "cbc") resultData = isEncrypt ? EncryptStandard<CBC_Mode<AES>::Encryption>(inputData, key, iv) : DecryptStandard<CBC_Mode<AES>::Decryption>(inputData, key, iv);
            else if (mode == "cfb") resultData = isEncrypt ? EncryptStandard<CFB_Mode<AES>::Encryption>(inputData, key, iv) : DecryptStandard<CFB_Mode<AES>::Decryption>(inputData, key, iv);
            else if (mode == "ofb") resultData = isEncrypt ? EncryptStandard<OFB_Mode<AES>::Encryption>(inputData, key, iv) : DecryptStandard<OFB_Mode<AES>::Decryption>(inputData, key, iv);
            else if (mode == "ctr") resultData = isEncrypt ? EncryptStandard<CTR_Mode<AES>::Encryption>(inputData, key, iv) : DecryptStandard<CTR_Mode<AES>::Decryption>(inputData, key, iv);
            else if (mode == "xts") resultData = isEncrypt ? EncryptStandard<XTS_Mode<AES>::Encryption>(inputData, key, iv) : DecryptStandard<XTS_Mode<AES>::Decryption>(inputData, key, iv);
            else if (mode == "gcm") resultData = isEncrypt ? EncryptAEAD<GCM<AES>::Encryption>(inputData, key, iv, actualAad, tagHex) : DecryptAEAD<GCM<AES>::Decryption>(inputData, key, iv, actualAad, tagHex);
            else if (mode == "ccm") resultData = isEncrypt ? EncryptAEAD<CCM<AES>::Encryption>(inputData, key, iv, actualAad, tagHex) : DecryptAEAD<CCM<AES>::Decryption>(inputData, key, iv, actualAad, tagHex);
        } catch (const CryptoPP::Exception& e) {
            if (!inputData.empty()) CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&inputData[0]), inputData.size());
            throw std::runtime_error(std::string("Crypto++ Engine Error: ") + e.what()); 
        }

        if (isEncrypt) {
            meta.alg = "AES-" + std::to_string(key.size() * 8) + "-" + mode;
            meta.mode = mode;
            if (iv.size() > 0) meta.iv_hex = HexEncode(std::string(reinterpret_cast<const char*>(iv.data()), iv.size()));
            if (!actualAad.empty()) meta.aad_hex = HexEncode(actualAad);
            if (!tagHex.empty()) meta.tag_hex = tagHex;
            
            if (outFormat == OutputFormat::BASE64) resultData = Base64Encode(resultData);
            else if (outFormat == OutputFormat::HEX) resultData = HexEncode(resultData);

            if (outFile.empty()) {
                std::cout << resultData << "\n";
            } else {
                WriteFileBinary(outFile, resultData);
                SaveSidecar(outFile + ".json", meta);
                if (isVerbose) std::cout << "[INFO] Sidecar metadata saved to: " << outFile << ".json\n";
            }
        } else {
            if (outFile.empty()) {
                std::cout << (outFormat == OutputFormat::BINARY ? HexEncode(resultData) : resultData) << "\n";
            } else {
                WriteFileBinary(outFile, resultData);
            }
        }

        if (!inputData.empty()) CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&inputData[0]), inputData.size());
        if (!resultData.empty()) CryptoPP::SecureWipeArray(reinterpret_cast<byte*>(&resultData[0]), resultData.size());
    }
};

// =========================================================
// KAT RUNNER (INTEGRATED)
// =========================================================
class KAT_Runner {
public:
    static void Run(const std::string& filepath) {
        std::vector<std::map<std::string, std::string>> kats;
        
        try {
            kats = ParseSimpleJsonArray(filepath);
        } catch (const std::exception& e) {
            std::cerr << "[!] JSON Error: Không thể đọc file vectors: " << e.what() << "\n";
            return;
        }

        int passed = 0, failed = 0, total = kats.size();
        std::cout << "=================================================\n";
        std::cout << "  RUNNING KNOWN ANSWER TESTS (NIST KATs)\n";
        std::cout << "=================================================\n";

        for (const auto& tc : kats) {
            std::string name = GetVal(tc, "test_name", "Unknown Test");
            bool result = false;
            try {
                result = TestSingle(tc);
            } catch (const CryptoPP::Exception& e) { 
                result = false;
            } catch (const std::exception& e) {
                result = false;
            }

            if (result) {
                std::cout << "[PASS] " << name << " (Enc & Dec)\n";
                passed++;
            } else {
                std::cout << "[FAIL] " << name << "\n";
                failed++;
            }
        }
        std::cout << "-------------------------------------------------\n";
        std::cout << "Summary: Total: " << total << " | Passed: " << passed << " | Failed: " << failed << "\n";
        if (failed == 0 && total > 0) {
            std::cout << ">>> ALL KATs PASSED SUCCESSFULLY. <<<\n";
        }
        std::cout << "=================================================\n";
    }

private:
    static void DecodeHexToBlock(const std::string& hexStr, SecByteBlock& block) {
        std::string decoded = HexDecode(hexStr);
        block.Assign(reinterpret_cast<const byte*>(decoded.data()), decoded.size());
    }

    static std::vector<std::map<std::string, std::string>> ParseSimpleJsonArray(const std::string& filepath) {
        std::vector<std::map<std::string, std::string>> array;
        std::string content = ReadFileBinary(filepath);
        
        std::map<std::string, std::string> currentObj;
        bool inString = false;
        std::string currentKey = "";
        std::string currentVal = "";
        bool expectingVal = false;
        
        std::string token = "";
        for (size_t i = 0; i < content.size(); ++i) {
            char c = content[i];
            if (c == '"') {
                inString = !inString;
                if (!inString) { 
                    if (!expectingVal) {
                        currentKey = token;
                    } else {
                        currentVal = token;
                        currentObj[currentKey] = currentVal;
                        currentKey.clear(); currentVal.clear();
                        expectingVal = false;
                    }
                    token.clear();
                }
                continue;
            }
            if (inString) token += c;
            else {
                if (c == '{') currentObj.clear();
                else if (c == '}') {
                    if (!currentObj.empty()) array.push_back(currentObj);
                    currentObj.clear();
                } else if (c == ':') expectingVal = true;
            }
        }
        return array;
    }

    static std::string GetVal(const std::map<std::string, std::string>& m, const std::string& key, const std::string& def = "") {
        auto it = m.find(key);
        return (it != m.end()) ? it->second : def;
    }

    static bool TestSingle(const std::map<std::string, std::string>& tc) {
        std::string mode = GetVal(tc, "mode");
        SecByteBlock key, iv;
        DecodeHexToBlock(GetVal(tc, "key"), key);
        DecodeHexToBlock(GetVal(tc, "iv"), iv);

        SecByteBlock ptBlock, expectedCtBlock;
        DecodeHexToBlock(GetVal(tc, "plaintext"), ptBlock);
        DecodeHexToBlock(GetVal(tc, "ciphertext"), expectedCtBlock);

        std::string pt((const char*)ptBlock.data(), ptBlock.size());
        std::string expectedCt((const char*)expectedCtBlock.data(), expectedCtBlock.size());
        std::string actualCt, actualPt;

        if (mode == "ecb" || mode == "cbc" || mode == "ofb" || mode == "cfb" || mode == "ctr" || mode == "xts") {
            // 1. Forward Cipher Test
            if (mode == "cbc") actualCt = EncryptMem<CBC_Mode<AES>::Encryption>(pt, key, iv);
            else if (mode == "cfb") actualCt = EncryptMem<CFB_Mode<AES>::Encryption>(pt, key, iv);
            else if (mode == "ofb") actualCt = EncryptMem<OFB_Mode<AES>::Encryption>(pt, key, iv);
            else if (mode == "ctr") actualCt = EncryptMem<CTR_Mode<AES>::Encryption>(pt, key, iv);
            else if (mode == "xts") actualCt = EncryptMem<XTS_Mode<AES>::Encryption>(pt, key, iv);
            else if (mode == "ecb") actualCt = EncryptMem<ECB_Mode<AES>::Encryption>(pt, key, iv);
            
            // 2. Inverse Cipher Test
            if (mode == "cbc") actualPt = DecryptMem<CBC_Mode<AES>::Decryption>(expectedCt, key, iv);
            else if (mode == "cfb") actualPt = DecryptMem<CFB_Mode<AES>::Decryption>(expectedCt, key, iv);
            else if (mode == "ofb") actualPt = DecryptMem<OFB_Mode<AES>::Decryption>(expectedCt, key, iv);
            else if (mode == "ctr") actualPt = DecryptMem<CTR_Mode<AES>::Decryption>(expectedCt, key, iv);
            else if (mode == "xts") actualPt = DecryptMem<XTS_Mode<AES>::Decryption>(expectedCt, key, iv);
            else if (mode == "ecb") actualPt = DecryptMem<ECB_Mode<AES>::Decryption>(expectedCt, key, iv);

            return (actualCt == expectedCt) && (actualPt == pt);
        } 
        else if (mode == "gcm" || mode == "ccm") {
            SecByteBlock aadBlock;
            DecodeHexToBlock(GetVal(tc, "aad"), aadBlock);
            std::string aad((const char*)aadBlock.data(), aadBlock.size());
            std::string expectedTagHex = GetVal(tc, "tag");
            std::string actualTagHex;

            // 1. Forward AEAD Test
            if (mode == "gcm") actualCt = EncryptAEADMem<GCM<AES>::Encryption>(pt, key, iv, aad, actualTagHex);
            else if (mode == "ccm") actualCt = EncryptAEADMem<CCM<AES>::Encryption>(pt, key, iv, aad, actualTagHex);

            std::transform(expectedTagHex.begin(), expectedTagHex.end(), expectedTagHex.begin(), ::toupper);
            std::transform(actualTagHex.begin(), actualTagHex.end(), actualTagHex.begin(), ::toupper);
            bool encSuccess = (actualCt == expectedCt) && (actualTagHex == expectedTagHex);

            // 2. Inverse AEAD Test (Bao gồm Tag Verification)
            bool decSuccess = false;
            try {
                if (mode == "gcm") actualPt = DecryptAEADMem<GCM<AES>::Decryption>(expectedCt, key, iv, aad, expectedTagHex);
                else if (mode == "ccm") actualPt = DecryptAEADMem<CCM<AES>::Decryption>(expectedCt, key, iv, aad, expectedTagHex);
                decSuccess = (actualPt == pt);
            } catch (const CryptoPP::Exception& e) {
                // Sẽ ném ngoại lệ nếu Tag sai lệch
                decSuccess = false;
            }

            return encSuccess && decSuccess;
        }
        return false;
    }

    template<class ENC_MODE>
    static std::string EncryptMem(const std::string& pt, const SecByteBlock& key, const SecByteBlock& iv) {
        ENC_MODE enc;
        if (iv.size() > 0 && enc.IVRequirement() != SimpleKeyingInterface::NOT_RESYNCHRONIZABLE) {
            enc.SetKeyWithIV(key, key.size(), iv, iv.size());
        } else enc.SetKey(key, key.size());

        std::string ct;
        StringSource ss(pt, true, new StreamTransformationFilter(enc, new StringSink(ct), StreamTransformationFilter::NO_PADDING));
        return ct;
    }

    template<class DEC_MODE>
    static std::string DecryptMem(const std::string& ct, const SecByteBlock& key, const SecByteBlock& iv) {
        DEC_MODE dec;
        if (iv.size() > 0 && dec.IVRequirement() != SimpleKeyingInterface::NOT_RESYNCHRONIZABLE) {
            dec.SetKeyWithIV(key, key.size(), iv, iv.size());
        } else dec.SetKey(key, key.size());

        std::string pt;
        StringSource ss(ct, true, new StreamTransformationFilter(dec, new StringSink(pt), StreamTransformationFilter::NO_PADDING));
        return pt;
    }

    template<class AEAD_ENC>
    static std::string EncryptAEADMem(const std::string& pt, const SecByteBlock& key, const SecByteBlock& iv, const std::string& aad, std::string& outTagHex) {
        AEAD_ENC enc;
        enc.SetKeyWithIV(key, key.size(), iv, iv.size());
        enc.SpecifyDataLengths(aad.size(), pt.size(), 0);

        std::string ct;
        // FIX: Bỏ cờ 'false, 16' để Crypto++ dùng behavior mặc định (Ciphertext + MAC)
        AuthenticatedEncryptionFilter ef(enc, new StringSink(ct));

        if (!aad.empty()) {
            ef.ChannelPut(AAD_CHANNEL, (const byte*)aad.data(), aad.size());
            ef.ChannelMessageEnd(AAD_CHANNEL);
        }
        ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)pt.data(), pt.size());
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);

        // ct lúc này chứa cả Ciphertext và MAC ở cuối
        outTagHex = HexEncode(ct.substr(pt.size())); 
        return ct.substr(0, pt.size());
    }

    template<class AEAD_DEC>
    static std::string DecryptAEADMem(const std::string& ct, const SecByteBlock& key, const SecByteBlock& iv, const std::string& aad, const std::string& expectedTagHex) {
        AEAD_DEC dec;
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());
        dec.SpecifyDataLengths(aad.size(), ct.size(), 0);

        std::string tag = HexDecode(expectedTagHex);
        std::string pt;

        // FIX SÂU: Khai báo rõ tagSize từ dữ liệu hex. Tránh lỗi TruncatedFinalization của KAT.
        int tagSize = static_cast<int>(tag.size());
        AuthenticatedDecryptionFilter df(dec, new StringSink(pt), 
            AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION, tagSize);

        if (!aad.empty()) {
            df.ChannelPut(AAD_CHANNEL, (const byte*)aad.data(), aad.size());
            df.ChannelMessageEnd(AAD_CHANNEL);
        }
        
        df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ct.data(), ct.size());
        df.ChannelPut(DEFAULT_CHANNEL, (const byte*)tag.data(), tag.size());
        df.ChannelMessageEnd(DEFAULT_CHANNEL);

        return pt;
    }
};

} // namespace

// =========================================================
// EXPORT C-API (CROSS-PLATFORM DLL/SO EXPORTS)
// =========================================================

AESTOOL_API int api_aestool_keygen(const char* out_file, char* err_msg, uint32_t err_size) {
    try {
        if (!out_file) throw std::invalid_argument("Output file path cannot be null");
        AES_App::GenerateKey(out_file);
        WriteError(err_msg, err_size, "");
        return AESTOOL_SUCCESS;
    } catch (const std::exception& e) {
        WriteError(err_msg, err_size, e.what());
        return AESTOOL_ERR_EXCEPTION;
    }
}

AESTOOL_API int api_aestool_encrypt(const char* mode, const char* key_path, const char* in_file, const char* out_file, const char* aad_file, char* err_msg, uint32_t err_size) {
    try {
        if (!mode || !key_path || !in_file || !out_file) throw std::invalid_argument("Core paths cannot be null");
        std::string modeStr = ToLower(mode);
        std::string keyData = ReadFileBinary(key_path);
        std::string keyRaw = IsHexString(keyData.substr(0, keyData.find_last_not_of(" \r\n\t") + 1)) ? HexDecode(keyData) : keyData;
        std::string aadStr = (aad_file && std::strlen(aad_file) > 0) ? ReadFileBinary(aad_file) : "";

        // [SỬA TẠI ĐÂY]: Đóng gói thành struct
        CryptoConfig cfg;
        cfg.isEncrypt = true;
        cfg.mode = modeStr;
        cfg.keyRaw = keyRaw;
        cfg.inMode = InputMode::FILE;
        cfg.inValue = in_file;
        cfg.outFile = out_file;
        cfg.outFormat = OutputFormat::BINARY;
        cfg.aadRaw = aadStr;

        AES_App::Process(cfg); // Gọi hàm chuẩn xác
        WriteError(err_msg, err_size, "");
        return AESTOOL_SUCCESS;
    } catch (const std::exception& e) {
        WriteError(err_msg, err_size, std::string("Encryption failed: ") + e.what());
        return AESTOOL_ERR_EXCEPTION;
    }
}

AESTOOL_API int api_aestool_decrypt(const char* mode, const char* key_path, const char* in_file, const char* out_file, const char* aad_file, char* err_msg, uint32_t err_size) {
    try {
        if (!mode || !key_path || !in_file || !out_file) throw std::invalid_argument("Core paths cannot be null");
        std::string modeStr = ToLower(mode);
        std::string keyData = ReadFileBinary(key_path);
        std::string keyRaw = IsHexString(keyData.substr(0, keyData.find_last_not_of(" \r\n\t") + 1)) ? HexDecode(keyData) : keyData;
        std::string aadStr = (aad_file && std::strlen(aad_file) > 0) ? ReadFileBinary(aad_file) : "";

        // [SỬA TẠI ĐÂY]: Đóng gói thành struct
        CryptoConfig cfg;
        cfg.isEncrypt = false;
        cfg.mode = modeStr;
        cfg.keyRaw = keyRaw;
        cfg.inMode = InputMode::FILE;
        cfg.inValue = in_file;
        cfg.outFile = out_file;
        cfg.outFormat = OutputFormat::BINARY;
        cfg.aadRaw = aadStr;

        AES_App::Process(cfg); // Gọi hàm chuẩn xác
        WriteError(err_msg, err_size, "");
        return AESTOOL_SUCCESS;
    } catch (const std::exception& e) {
        WriteError(err_msg, err_size, std::string("Decryption failed: ") + e.what());
        return AESTOOL_ERR_EXCEPTION;
    }
}


// =========================================================
// COMMAND LINE INTERFACE (CLI)
// =========================================================
#ifndef AESTOOL_NO_MAIN
void PrintUsage(const char* prog) {
    std::cerr
        << "Usage:\n"
        << "  " << prog << " keygen --out <keyfile.hex>\n"
        << "  " << prog << " encrypt [--in INFILE | --text \"...\"] [--out OUTFILE] [--key KEYFILE | --key-hex HEX] [--mode MODE] [options...]\n"
        << "  " << prog << " decrypt [--in INFILE | --text \"...\"] [--out OUTFILE] [--key KEYFILE | --key-hex HEX] [--mode MODE] [options...]\n"
        << "  " << prog << " --kat <path/to/vectors.json>\n\n"
        << "Run '" << prog << " --help' for full options.\n";
}

void PrintHelp(const char* prog) {
    std::cerr << "=========================================================\n";
    std::cerr << "          AESTOOL - Symmetric Encryption Utility         \n";
    std::cerr << "=========================================================\n\n";
    PrintUsage(prog);
    std::cerr
        << "\nCORE OPTIONS:\n"
        << "  --mode <mode>      ecb | cbc | ofb | cfb | ctr | xts | gcm | ccm\n"
        << "  --key <path>       Path to AES key file (Raw Binary or Hex).\n"
        << "  --key-hex <hex>    Provide AES key directly as Hex string.\n"
        << "  --in <path>        Input file (Binary-safe).\n"
        << "  --text <string>    Input plain text directly (UTF-8).\n"
        << "  --out <path>       Output file (Binary-safe). Screen output if omitted.\n"
        << "\nFORMAT & ENCODING:\n"
        << "  --encode <fmt>     hex | base64 | raw (Default screen: hex, file: raw)\n"
        << "  --iv <file|hex>    Custom IV/Nonce. Auto-generated if omitted.\n"
        << "  --nonce <file|hex> Alias for --iv.\n"
        << "\nAEAD OPTIONS (Required for GCM/CCM):\n"
        << "  --aead             Must be set when using AEAD modes.\n"
        << "  --aad <path>       File containing Additional Authenticated Data.\n"
        << "  --aad-text <str>   AAD directly as a UTF-8 string.\n"
        << "  --tag <hex>        Expected authentication tag (Decryption only).\n"
        << "\nMISC / COMPATIBILITY:\n"
        << "  --allow-ecb        Bypass ECB mode 16KiB restriction.\n"
        << "  --threads <N>      Thread count for uniform lab compability.\n"
        << "  --verbose          Enable detailed execution logs.\n"
        << "  --kat <path>       Run NIST Known Answer Tests from JSON.\n"
        << "=========================================================\n";
}

class CliParser {
public:
    static CryptoConfig Parse(int argc, char* argv[], const std::string& command) {
        CryptoConfig cfg;
        cfg.isEncrypt = (command == "encrypt");
        
        std::map<std::string, std::string> args;
        std::set<std::string> flags; // Lưu các cờ không có giá trị đi kèm (như --aead, --verbose)

        // 1. Quét toàn bộ tham số
        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--verbose" || arg == "--allow-ecb" || arg == "--aead") {
                flags.insert(arg);
                continue;
            }
            if (arg.rfind("--", 0) == 0) {
                if (i + 1 >= argc || argv[i+1][0] == '-') {
                    throw std::invalid_argument("Fail Closed: Thiếu giá trị cho tham số " + arg);
                }
                if (args.count(arg)) {
                    throw std::invalid_argument("Fail Closed: Tham số " + arg + " bị lặp lại.");
                }
                args[arg] = argv[++i];
            } else {
                throw std::invalid_argument("Fail Closed: Tham số không hợp lệ " + arg);
            }
        }

        // 2. Gán flags
        cfg.isVerbose = flags.count("--verbose");
        cfg.allowEcb = flags.count("--allow-ecb");
        cfg.isAead = flags.count("--aead");
        if (args.count("--threads")) cfg.threads = std::stoi(args["--threads"]);

        // 3. Ràng buộc Mode & AEAD
        if (!args.count("--mode")) throw std::invalid_argument("Fail Closed: Bắt buộc phải có --mode.");
        cfg.mode = ToLower(args["--mode"]);
        
        if ((cfg.mode == "gcm" || cfg.mode == "ccm") && !cfg.isAead) {
            throw std::invalid_argument("Fail Closed: Mode " + cfg.mode + " yêu cầu cờ --aead.");
        }

        // 4. Xử lý Key
        if (args.count("--key-hex")) {
            cfg.keyRaw = HexDecode(args["--key-hex"]);
        } else if (args.count("--key")) {
            std::string kData = ReadFileBinary(args["--key"]);
            cfg.keyRaw = IsHexString(kData.substr(0, kData.find_last_not_of(" \r\n\t") + 1)) ? HexDecode(kData) : kData;
        } else {
            throw std::invalid_argument("Fail Closed: Thiếu --key hoặc --key-hex.");
        }

        // 5. Xử lý Input
        bool hasIn = args.count("--in");
        bool hasText = args.count("--text");
        if (hasIn == hasText) throw std::invalid_argument("Fail Closed: Phải có đúng một đầu vào (--in HOẶC --text).");
        
        cfg.inMode = hasText ? InputMode::TEXT : InputMode::FILE;
        cfg.inValue = hasText ? args["--text"] : args["--in"];
        cfg.outFile = args.count("--out") ? args["--out"] : "";

        // 6. Quy tắc Output mặc định theo PDF (Màn hình = Hex, File = Raw)
        cfg.outFormat = cfg.outFile.empty() ? OutputFormat::HEX : OutputFormat::BINARY;
        if (args.count("--encode")) {
            if (!ParseEncodeFormat(args["--encode"], cfg.outFormat)) {
                throw std::invalid_argument("Fail Closed: --encode không hợp lệ (hex, base64, raw).");
            }
        }

        // 7. Xử lý IV & AAD
        std::string ivArg = args.count("--iv") ? args["--iv"] : (args.count("--nonce") ? args["--nonce"] : "");
        if (!ivArg.empty()) {
            if (fs::exists(ivArg)) {
                std::string ivFileContent = ReadFileBinary(ivArg);
                cfg.explicitIvRaw = IsHexString(ivFileContent) ? HexDecode(ivFileContent) : ivFileContent;
            } else {
                cfg.explicitIvRaw = HexDecode(ivArg); // Xử lý nếu user truyền thẳng hex thay vì tên file
            }
        }

        if (args.count("--aad-text")) cfg.aadRaw = args["--aad-text"];
        else if (args.count("--aad")) cfg.aadRaw = ReadFileBinary(args["--aad"]);

        cfg.explicitTagHex = args.count("--tag") ? args["--tag"] : "";

        return cfg;
    }
};

int main(int argc, char* argv[]) {
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    #endif

    if (argc < 2) { PrintUsage(argv[0]); return 1; }
    std::string command = argv[1];

    if (command == "--help" || command == "-h") { PrintHelp(argv[0]); return 0; }

    if (command == "--kat") {
        if (argc < 3) { std::cerr << "[!] Fail Closed: Missing path for --kat.\n"; return 1; }
        KAT_Runner::Run(argv[2]); 
        return 0;
    }

    try {
        if (command == "keygen") {
            // Tách riêng logic xử lý keygen cho gọn
            std::string outFile = "";
            for (int i = 2; i < argc; i++) {
                if (std::string(argv[i]) == "--out" && i + 1 < argc) outFile = argv[++i];
            }
            if (outFile.empty()) throw std::invalid_argument("Fail Closed: Missing --out parameter.");
            AES_App::GenerateKey(outFile);
            std::cout << "[+] Keygen successful.\n";
            return 0;
        }
        
        if (command == "encrypt" || command == "decrypt") {
            // Nhờ CLI Parser, main() giờ đây không chứa logic rác
            CryptoConfig cfg = CliParser::Parse(argc, argv, command);
            
            // Gọi lõi Crypto
            AES_App::Process(cfg); 
            
            if (!cfg.outFile.empty()) {
                std::cout << "[+] " << (cfg.isEncrypt ? "Encryption" : "Decryption") << " successful.\n";
            }
            return 0;
        }
        
        std::cerr << "Unknown command: " << command << "\n";
        PrintUsage(argv[0]);
        return 1;

    } catch (const std::exception& e) {
        std::cerr << "[!] CRITICAL ERROR: " << e.what() << "\n";
        return 1;
    }
}
#endif