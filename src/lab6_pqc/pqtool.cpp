#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <map>
#include <set>
#include <stdexcept>
#include <cstring>
#include <cctype>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

// ---------------------------------------------------------
// MACROS FOR DLL/SO EXPORT (CROSS-PLATFORM)
// ---------------------------------------------------------
#ifdef _WIN32
  #ifdef PQTOOL_BUILD_DLL
    #define PQTOOL_API extern "C" __declspec(dllexport)
  #elif defined(PQTOOL_USE_DLL)
    #define PQTOOL_API extern "C" __declspec(dllimport)
  #else
    #define PQTOOL_API extern "C"
  #endif
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define PQTOOL_API extern "C" __attribute__((visibility("default")))
  #else
    #define PQTOOL_API extern "C"
  #endif
#endif

#define PQC_SUCCESS 0
#define PQC_ERR_EXCEPTION -1

// ============================================================================
// UTILITIES (Encoding, File I/O, JSON Parser)
// ============================================================================
namespace util {

    enum class OutputFormat { BINARY, HEX, BASE64 };
    enum class InputMode { TEXT, FILE };

    std::string ToLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

    std::string GetBasePrefix(const std::string& path) {
        size_t dotPos = path.find_last_of('.');
        size_t sepPos = path.find_last_of("/\\"); 
        if (dotPos != std::string::npos && (sepPos == std::string::npos || dotPos > sepPos)) {
            return path.substr(0, dotPos); 
        }
        return path;
    }

    // --- Base64 ---
    const std::string B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string Base64Encode(const uint8_t* buf, size_t len) {
        std::string ret; int i = 0, j = 0; uint8_t char_array_3[3], char_array_4[4];
        while (len--) {
            char_array_3[i++] = *(buf++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;
                for(i = 0; (i < 4); i++) ret += B64_CHARS[char_array_4[i]];
                i = 0;
            }
        }
        if (i) {
            for(j = i; j < 3; j++) char_array_3[j] = '\0';
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            for (j = 0; (j < i + 1); j++) ret += B64_CHARS[char_array_4[j]];
            while((i++ < 3)) ret += '=';
        }
        return ret;
    }

    std::vector<uint8_t> Base64Decode(const std::string& encoded_string) {
        size_t in_len = encoded_string.size(); int i = 0, j = 0, in_ = 0; 
        uint8_t char_array_4[4], char_array_3[3]; std::vector<uint8_t> ret;
        while (in_len-- && (encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++) char_array_4[i] = B64_CHARS.find(char_array_4[i]);
                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
                for (i = 0; (i < 3); i++) ret.push_back(char_array_3[i]);
                i = 0;
            }
        }
        if (i) {
            for (j = i; j < 4; j++) char_array_4[j] = 0;
            for (j = 0; j < 4; j++) char_array_4[j] = B64_CHARS.find(char_array_4[j]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
        }
        return ret;
    }

    // --- Hex ---
    std::string HexEncode(const uint8_t* data, size_t len) {
        if (!data || len == 0) return "";
        static const char hexChars[] = "0123456789abcdef";
        std::string encoded;
        encoded.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            encoded.push_back(hexChars[(data[i] >> 4) & 0x0F]);
            encoded.push_back(hexChars[data[i] & 0x0F]);
        }
        return encoded;
    }

    std::vector<uint8_t> HexDecodeBytes(const std::string& hex) {
        std::vector<uint8_t> decoded;
        auto isHex = [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); };
        auto hexVal = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return 0;
        };
        std::string cleanHex;
        for (char c : hex) if (isHex(c)) cleanHex.push_back(c);
        if (cleanHex.size() % 2 != 0) throw std::invalid_argument("Hex string format error: odd number of valid digits.");
        
        decoded.reserve(cleanHex.size() / 2);
        for (size_t i = 0; i < cleanHex.size(); i += 2) {
            decoded.push_back((hexVal(cleanHex[i]) << 4) | hexVal(cleanHex[i + 1]));
        }
        return decoded;
    }

    // --- Format Handlers ---
    std::string FormatData(const std::vector<uint8_t>& data, OutputFormat fmt) {
        if (fmt == OutputFormat::HEX) return HexEncode(data.data(), data.size());
        if (fmt == OutputFormat::BASE64) return Base64Encode(data.data(), data.size());
        return std::string(data.begin(), data.end());
    }

    std::vector<uint8_t> ParseData(const std::string& input, OutputFormat fmt) {
        if (fmt == OutputFormat::HEX) return HexDecodeBytes(input);
        if (fmt == OutputFormat::BASE64) return Base64Decode(input);
        return std::vector<uint8_t>(input.begin(), input.end());
    }

    // --- File I/O ---
    std::vector<uint8_t> ReadFileBinary(const std::string& filename) {
        std::ifstream in(filename, std::ios::binary);
        if (!in) throw std::runtime_error("Failed to open file: " + filename);
        return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }

    std::string ReadFileString(const std::string& filename) {
        std::ifstream in(filename, std::ios::binary);
        if (!in) throw std::runtime_error("Failed to open file: " + filename);
        return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }

    void SaveOutput(const std::string& path, const std::vector<uint8_t>& data, OutputFormat fmt) {
        std::string formatted = FormatData(data, fmt);
        if (path.empty()) {
            std::cout << formatted << "\n";
        } else {
            std::ofstream out(path, std::ios::binary);
            if (!out) throw std::runtime_error("Failed to write to file: " + path);
            out.write(formatted.data(), formatted.size());
        }
    }

    // --- JSON ---
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
                while (pos < jsonStr.length() && jsonStr[pos] != ',' && jsonStr[pos] != '}' && !std::isspace(jsonStr[pos])) pos++;
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
            if (std::find(numericKeys.begin(), numericKeys.end(), pair.first) != numericKeys.end()) json += pair.second;
            else json += "\"" + pair.second + "\"";
            first = false;
        }
        json += "\n}";
        return json;
    }

    void HandleOpenSSLErrors(const std::string& context) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        throw std::runtime_error(context + ": " + std::string(err_buf));
    }
}

// ============================================================================
// OPENSSL 3.5+ POST-QUANTUM CORE
// ============================================================================
class PQC_App {
private:
    // Tự động detect và load PEM hoặc DER từ buffer an toàn trên RAM
    static EVP_PKEY* LoadKey(const std::string& path, bool isPublic) {
        std::vector<uint8_t> data = util::ReadFileBinary(path);
        BIO* bio = BIO_new_mem_buf(data.data(), data.size());
        if (!bio) throw std::runtime_error("Failed to allocate BIO memory for key: " + path);
        
        EVP_PKEY* pkey = nullptr;
        if (isPublic) {
            pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            if (!pkey) {
                BIO_reset(bio);
                pkey = d2i_PUBKEY_bio(bio, nullptr);
            }
        } else {
            pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            if (!pkey) {
                BIO_reset(bio);
                pkey = d2i_PrivateKey_bio(bio, nullptr);
            }
        }
        BIO_free(bio);
        if (!pkey) util::HandleOpenSSLErrors("Failed to load key from " + path + " (Invalid PEM/DER format)");
        return pkey;
    }

public:
    static void Init() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    static std::string NormalizeAlgoName(const std::string& input) {
        std::string algo = input;
        std::transform(algo.begin(), algo.end(), algo.begin(), ::toupper);
        if (algo == "MLDSA-44") return "ML-DSA-44";
        if (algo == "MLDSA-65") return "ML-DSA-65";
        if (algo == "MLDSA-87") return "ML-DSA-87";
        if (algo == "MLKEM-512") return "ML-KEM-512";
        if (algo == "MLKEM-768") return "ML-KEM-768";
        if (algo == "MLKEM-1024") return "ML-KEM-1024";
        return algo;
    }

    static void KeyGen(const std::string& algo, const std::string& pub_path, const std::string& priv_path) {
        std::string ossl_algo = NormalizeAlgoName(algo);
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, ossl_algo.c_str(), nullptr);
        if (!ctx) util::HandleOpenSSLErrors("Context creation failed for " + ossl_algo);

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen_init(ctx) <= 0) util::HandleOpenSSLErrors("Keygen init failed");
        if (EVP_PKEY_generate(ctx, &pkey) <= 0) util::HandleOpenSSLErrors("Key generation failed");

        std::string pubBase = util::GetBasePrefix(pub_path);
        std::string privBase = util::GetBasePrefix(priv_path);

        // Xuất PEM Format
        BIO* outPubPem = BIO_new_file((pubBase + ".pem").c_str(), "w");
        if (!outPubPem || !PEM_write_bio_PUBKEY(outPubPem, pkey)) throw std::runtime_error("Failed to write PEM public key");
        BIO_free(outPubPem);

        BIO* outPrivPem = BIO_new_file((privBase + ".pem").c_str(), "w");
        if (!outPrivPem || !PEM_write_bio_PrivateKey(outPrivPem, pkey, nullptr, nullptr, 0, nullptr, nullptr)) throw std::runtime_error("Failed to write PEM private key");
        BIO_free(outPrivPem);

        // Xuất DER Format
        BIO* outPubDer = BIO_new_file((pubBase + ".der").c_str(), "wb");
        if (!outPubDer || !i2d_PUBKEY_bio(outPubDer, pkey)) throw std::runtime_error("Failed to write DER public key");
        BIO_free(outPubDer);

        BIO* outPrivDer = BIO_new_file((privBase + ".der").c_str(), "wb");
        if (!outPrivDer || !i2d_PrivateKey_bio(outPrivDer, pkey)) throw std::runtime_error("Failed to write DER private key");
        BIO_free(outPrivDer);

        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        std::cout << "[SUCCESS] Generated " << ossl_algo << " keypair (Saved as PEM and DER).\n";
    }

    static void Sign(const std::string& priv_path, util::InputMode inMode, const std::string& inValue, const std::string& out_path, util::OutputFormat fmt) {
        EVP_PKEY* pkey = LoadKey(priv_path, false);

        std::string msg_str = (inMode == util::InputMode::TEXT) ? inValue : util::ReadFileString(inValue);
        std::vector<uint8_t> msg(msg_str.begin(), msg_str.end());

        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        if (!mctx) throw std::runtime_error("Failed to create MD context");

        if (EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, pkey) <= 0) util::HandleOpenSSLErrors("SignInit failed");
        
        size_t sig_len = 0;
        if (EVP_DigestSign(mctx, nullptr, &sig_len, msg.data(), msg.size()) <= 0) util::HandleOpenSSLErrors("Sign size estimation failed");
        
        std::vector<uint8_t> sig(sig_len);
        if (EVP_DigestSign(mctx, sig.data(), &sig_len, msg.data(), msg.size()) <= 0) util::HandleOpenSSLErrors("Signature generation failed");
        
        sig.resize(sig_len);
        util::SaveOutput(out_path, sig, fmt);

        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        if (!out_path.empty()) std::cout << "[SUCCESS] Created detached ML-DSA signature.\n";
    }

    static void Verify(const std::string& pub_path, util::InputMode inMode, const std::string& inValue, const std::string& sig_path, util::OutputFormat fmt) {
        EVP_PKEY* pkey = LoadKey(pub_path, true);

        std::string msg_str = (inMode == util::InputMode::TEXT) ? inValue : util::ReadFileString(inValue);
        std::vector<uint8_t> msg(msg_str.begin(), msg_str.end());

        std::string sig_str = util::ReadFileString(sig_path);
        std::vector<uint8_t> sig = util::ParseData(sig_str, fmt);

        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        if (!mctx) throw std::runtime_error("Failed to create MD context");

        if (EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, pkey) <= 0) util::HandleOpenSSLErrors("VerifyInit failed");
        
        int ret = EVP_DigestVerify(mctx, sig.data(), sig.size(), msg.data(), msg.size());
        
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);

        if (ret == 1) {
            std::cout << "[SUCCESS] Verification MATCH: Data integrity confirmed.\n";
        } else {
            std::cout << "[FAILURE] Verification FAILED: Invalid signature or corrupted data.\n";
        }
    }

    static void Encaps(const std::string& pub_path, const std::string& ct_path, const std::string& ss_path, util::OutputFormat fmt) {
        EVP_PKEY* pkey = LoadKey(pub_path, true);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) throw std::runtime_error("Context creation failed");

        if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0) util::HandleOpenSSLErrors("Encapsulate init failed");

        size_t ct_len = 0, ss_len = 0;
        if (EVP_PKEY_encapsulate(ctx, nullptr, &ct_len, nullptr, &ss_len) <= 0) util::HandleOpenSSLErrors("Encapsulate length check failed");

        std::vector<uint8_t> ct(ct_len), ss(ss_len);
        if (EVP_PKEY_encapsulate(ctx, ct.data(), &ct_len, ss.data(), &ss_len) <= 0) util::HandleOpenSSLErrors("Encapsulation failed");

        util::SaveOutput(ct_path, ct, fmt);
        util::SaveOutput(ss_path, ss, fmt);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        
        if (!ct_path.empty() && !ss_path.empty()) std::cout << "[SUCCESS] ML-KEM Encapsulation complete.\n";
    }

    static void Decaps(const std::string& priv_path, const std::string& ct_path, const std::string& ss_path, util::OutputFormat fmt) {
        EVP_PKEY* pkey = LoadKey(priv_path, false);

        std::string ct_str = util::ReadFileString(ct_path);
        std::vector<uint8_t> ct = util::ParseData(ct_str, fmt);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) throw std::runtime_error("Context creation failed");

        if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0) util::HandleOpenSSLErrors("Decapsulate init failed");

        size_t ss_len = 0;
        if (EVP_PKEY_decapsulate(ctx, nullptr, &ss_len, ct.data(), ct.size()) <= 0) util::HandleOpenSSLErrors("Decapsulate length check failed");

        std::vector<uint8_t> ss(ss_len);
        if (EVP_PKEY_decapsulate(ctx, ss.data(), &ss_len, ct.data(), ct.size()) <= 0) util::HandleOpenSSLErrors("Decapsulation failed");

        util::SaveOutput(ss_path, ss, fmt);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        
        if (!ss_path.empty()) std::cout << "[SUCCESS] ML-KEM Decapsulation complete.\n";
    }

    static void IssueCert(const std::string& sub_name, const std::string& sub_pub_pem, const std::string& ca_priv_pem, const std::string& out_json) {
        EVP_PKEY* sub_pkey = LoadKey(sub_pub_pem, true);
        EVP_PKEY* ca_pkey = LoadKey(ca_priv_pem, false);

        uint8_t* pub_der = nullptr;
        int pub_len = i2d_PUBKEY(sub_pkey, &pub_der);
        if(pub_len <= 0) util::HandleOpenSSLErrors("Failed to extract DER pubkey");
        std::string pub_b64 = util::Base64Encode(pub_der, pub_len);
        OPENSSL_free(pub_der);

        std::string tbs_data = sub_name + pub_b64 + "PQ-CA"; 

        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ca_pkey);
        
        size_t sig_len = 0;
        EVP_DigestSign(mctx, nullptr, &sig_len, reinterpret_cast<const uint8_t*>(tbs_data.data()), tbs_data.size());
        std::vector<uint8_t> signature(sig_len);
        EVP_DigestSign(mctx, signature.data(), &sig_len, reinterpret_cast<const uint8_t*>(tbs_data.data()), tbs_data.size());
        
        std::vector<std::pair<std::string, std::string>> cert_data = {
            {"subject", sub_name},
            {"public_key", pub_b64},
            {"issuer", "PQ-CA"},
            {"signature", util::Base64Encode(signature.data(), sig_len)}
        };
        
        std::string json_out = util::JsonEnvelopeStringify(cert_data, {});
        
        std::ofstream out(out_json);
        if (out.is_open()) {
            out << json_out;
            std::cout << "[SUCCESS] Formatted PQC JSON certificate created.\n";
        }

        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(sub_pkey);
        EVP_PKEY_free(ca_pkey);
    }

    static void VerifyCert(const std::string& cert_json_path, const std::string& ca_pub_pem) {
        std::ifstream in(cert_json_path);
        if (!in.is_open()) throw std::runtime_error("Cannot open certificate file");
        
        std::string jsonStr((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::map<std::string, std::string> cert;
        
        try {
            cert = util::JsonEnvelopeParse(jsonStr);
        } catch (...) {
            std::cout << "[FAILURE] Certificate validation FAILED. Invalid JSON format due to extreme tampering!\n";
            return;
        }

        EVP_PKEY* ca_pkey = LoadKey(ca_pub_pem, true);

        if (cert.find("subject") == cert.end() || cert.find("public_key") == cert.end() || 
            cert.find("issuer") == cert.end() || cert.find("signature") == cert.end()) {
            std::cout << "[FAILURE] Certificate validation FAILED. Missing required JSON structural elements!\n";
            EVP_PKEY_free(ca_pkey);
            return;
        }

        std::string tbs_data = cert["subject"] + cert["public_key"] + cert["issuer"];
        std::vector<uint8_t> signature = util::Base64Decode(cert["signature"]);

        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ca_pkey);
        
        int ret = EVP_DigestVerify(mctx, signature.data(), signature.size(), reinterpret_cast<const uint8_t*>(tbs_data.data()), tbs_data.size());
        
        if (ret == 1) {
            std::cout << "[SUCCESS] Certificate validation PASSED. Content is trusted.\n";
        } else {
            std::cout << "[FAILURE] Certificate validation FAILED. Data tampering detected!\n";
        }

        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(ca_pkey);
    }

    static void RunTests() {
        std::cout << "==================================================\n";
        std::cout << "          AUTOMATED PQC TESTING SUITE             \n";
        std::cout << "==================================================\n";

        EVP_PKEY_CTX* ctx_dsa = EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-44", nullptr);
        EVP_PKEY* pkey_dsa = nullptr;
        EVP_PKEY_keygen_init(ctx_dsa);
        EVP_PKEY_generate(ctx_dsa, &pkey_dsa);

        std::cout << "[*] Running ML-DSA-44 Functional & Negative Tests...\n";
        std::vector<uint8_t> msg = {'L', 'A', 'B', '6', ' ', 'P', 'Q', 'C'};
        
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, pkey_dsa);
        size_t sig_len = 0;
        EVP_DigestSign(mctx, nullptr, &sig_len, msg.data(), msg.size());
        std::vector<uint8_t> signature(sig_len);
        EVP_DigestSign(mctx, signature.data(), &sig_len, msg.data(), msg.size());

        EVP_MD_CTX* mctx_ver = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(mctx_ver, nullptr, nullptr, nullptr, pkey_dsa);
        if (EVP_DigestVerify(mctx_ver, signature.data(), sig_len, msg.data(), msg.size()) == 1) {
            std::cout << "  [PASS] Test 1: Normal Signature Verification Success.\n";
        } else {
            std::cout << "  [FAIL] Test 1: Normal Signature Verification Failed.\n";
        }

        std::vector<uint8_t> tampered_msg = msg;
        tampered_msg[0] ^= 0xFF; 
        EVP_DigestVerifyInit(mctx_ver, nullptr, nullptr, nullptr, pkey_dsa);
        if (EVP_DigestVerify(mctx_ver, signature.data(), sig_len, tampered_msg.data(), tampered_msg.size()) != 1) {
            std::cout << "  [PASS] Test 2: Modified Message Successfully Rejected!\n";
        }

        std::vector<uint8_t> tampered_sig = signature;
        tampered_sig[0] ^= 0xFF; 
        EVP_DigestVerifyInit(mctx_ver, nullptr, nullptr, nullptr, pkey_dsa);
        if (EVP_DigestVerify(mctx_ver, tampered_sig.data(), sig_len, msg.data(), msg.size()) != 1) {
            std::cout << "  [PASS] Test 3: Modified Signature Successfully Rejected!\n";
        }

        EVP_MD_CTX_free(mctx);
        EVP_MD_CTX_free(mctx_ver);

        std::cout << "\n[*] Running ML-KEM-512 Functional & Negative Tests...\n";
        EVP_PKEY_CTX* ctx_kem = EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-512", nullptr);
        EVP_PKEY* pkey_kem = nullptr;
        EVP_PKEY_keygen_init(ctx_kem);
        EVP_PKEY_generate(ctx_kem, &pkey_kem);

        EVP_PKEY_CTX* ctx_enc = EVP_PKEY_CTX_new(pkey_kem, nullptr);
        EVP_PKEY_encapsulate_init(ctx_enc, nullptr);
        size_t ct_len, ss_len;
        EVP_PKEY_encapsulate(ctx_enc, nullptr, &ct_len, nullptr, &ss_len);
        std::vector<uint8_t> ct(ct_len), ss_encap(ss_len);
        EVP_PKEY_encapsulate(ctx_enc, ct.data(), &ct_len, ss_encap.data(), &ss_len);

        EVP_PKEY_CTX* ctx_dec = EVP_PKEY_CTX_new(pkey_kem, nullptr);
        EVP_PKEY_decapsulate_init(ctx_dec, nullptr);
        size_t ss_dec_len;
        EVP_PKEY_decapsulate(ctx_dec, nullptr, &ss_dec_len, ct.data(), ct_len);
        std::vector<uint8_t> ss_decap(ss_dec_len);
        EVP_PKEY_decapsulate(ctx_dec, ss_decap.data(), &ss_dec_len, ct.data(), ct_len);

        if (ss_encap == ss_decap) {
            std::cout << "  [PASS] Test 5: Normal KEM Shared Secrets Match.\n";
        }

        std::vector<uint8_t> tampered_ct = ct;
        tampered_ct[0] ^= 0xFF; 
        std::vector<uint8_t> ss_decap_tampered(ss_dec_len);
        EVP_PKEY_decapsulate_init(ctx_dec, nullptr);
        EVP_PKEY_decapsulate(ctx_dec, ss_decap_tampered.data(), &ss_dec_len, tampered_ct.data(), ct_len);
        if (ss_encap != ss_decap_tampered) {
            std::cout << "  [PASS] Test 6: Modified Ciphertext Safely Rejected!\n";
        }

        EVP_PKEY_CTX_free(ctx_dsa); EVP_PKEY_free(pkey_dsa);
        EVP_PKEY_CTX_free(ctx_kem); EVP_PKEY_free(pkey_kem);
        EVP_PKEY_CTX_free(ctx_enc); EVP_PKEY_CTX_free(ctx_dec);
        
        std::cout << "==================================================\n";
    }
};


// ============================================================================
// COMMAND LINE INTERFACE & CONFIGURATION
// ============================================================================
struct CryptoConfig {
    std::string command;
    std::string algo;
    std::string pubPath;
    std::string privPath;
    
    util::InputMode inMode = util::InputMode::FILE;
    std::string inValue;
    
    std::string outPath;
    std::string sigPath;
    std::string ctPath;
    std::string ssPath;
    std::string certPath;
    std::string subject;
    
    util::OutputFormat encodeFormat = util::OutputFormat::BINARY;
};

void PrintUsage(const char* prog) {
    std::cerr << "Usage:\n"
              << "  " << prog << " keygen --algo <mldsa-44|mlkem-512> --pub <pub_prefix> --priv <priv_prefix>\n"
              << "  " << prog << " sign --algo <mldsa-44> --priv <priv.pem|der> (--in <msg.file> | --text \"...\") [--out <sig.bin>] [--encode hex|base64|raw]\n"
              << "  " << prog << " verify --algo <mldsa-44> --pub <pub.pem|der> (--in <msg.file> | --text \"...\") --sig <sig.bin> [--encode hex|base64|raw]\n"
              << "  " << prog << " encaps --algo <mlkem-512> --pub <pub.pem|der> [--ct <ct.bin>] [--ss <ss.bin>] [--encode hex|base64|raw]\n"
              << "  " << prog << " decaps --algo <mlkem-512> --priv <priv.pem|der> --ct <ct.bin> [--ss <ss.bin>] [--encode hex|base64|raw]\n"
              << "  " << prog << " issue-cert --subject <name> --pub <sub_pub.pem|der> --priv <ca_priv.pem|der> --out <cert.json>\n"
              << "  " << prog << " verify-cert --cert <cert.json> --pub <ca_pub.pem|der>\n"
              << "  " << prog << " run-tests\n";
}

class CliParser {
public:
    static CryptoConfig Parse(int argc, char* argv[]) {
        CryptoConfig cfg;
        cfg.command = argv[1];
        std::map<std::string, std::string> args;

        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg.rfind("--", 0) == 0) {
                if (i + 1 >= argc || argv[i+1][0] == '-') throw std::invalid_argument("Fail Closed: Missing value for " + arg);
                if (args.count(arg)) throw std::invalid_argument("Fail Closed: Duplicate argument " + arg);
                args[arg] = argv[++i];
            }
        }

        if (args.count("--algo")) cfg.algo = args["--algo"];
        if (args.count("--pub")) cfg.pubPath = args["--pub"];
        if (args.count("--priv")) cfg.privPath = args["--priv"];
        if (args.count("--out")) cfg.outPath = args["--out"];
        if (args.count("--sig")) cfg.sigPath = args["--sig"];
        if (args.count("--ct")) cfg.ctPath = args["--ct"];
        if (args.count("--ss")) cfg.ssPath = args["--ss"];
        if (args.count("--cert")) cfg.certPath = args["--cert"];
        if (args.count("--subject")) cfg.subject = args["--subject"];

        // Input parsing for sign/verify
        if (cfg.command == "sign" || cfg.command == "verify") {
            bool hasIn = args.count("--in");
            bool hasText = args.count("--text");
            if (hasIn == hasText) throw std::invalid_argument("Fail Closed: Specify exactly one input mode: --in OR --text.");
            cfg.inMode = hasText ? util::InputMode::TEXT : util::InputMode::FILE;
            cfg.inValue = hasText ? args["--text"] : args["--in"];
        }

        // Encode parsing
        if (args.count("--encode")) {
            std::string enc = util::ToLower(args["--encode"]);
            if (enc == "hex") cfg.encodeFormat = util::OutputFormat::HEX;
            else if (enc == "base64" || enc == "b64") cfg.encodeFormat = util::OutputFormat::BASE64;
            else if (enc == "raw" || enc == "bin" || enc == "binary") cfg.encodeFormat = util::OutputFormat::BINARY;
            else throw std::invalid_argument("Fail Closed: Invalid --encode value. Use raw, hex, or base64.");
        } else {
             bool hasOut = false;
             if (cfg.command == "sign" && !cfg.outPath.empty()) hasOut = true;
             if (cfg.command == "encaps" && (!cfg.ctPath.empty() || !cfg.ssPath.empty())) hasOut = true;
             if (cfg.command == "decaps" && !cfg.ssPath.empty()) hasOut = true;
             
             // Default PDF spec: Hex if screen, Raw if file
             cfg.encodeFormat = hasOut ? util::OutputFormat::BINARY : util::OutputFormat::HEX;
        }

        return cfg;
    }
};

int main(int argc, char* argv[]) {
    PQC_App::Init();

    if (argc < 2) { PrintUsage(argv[0]); return 1; }
    
    std::string cmd = argv[1];
    if (cmd == "--help" || cmd == "-h") { PrintUsage(argv[0]); return 0; }

    try {
        CryptoConfig cfg = CliParser::Parse(argc, argv);

        if (cmd == "keygen") PQC_App::KeyGen(cfg.algo, cfg.pubPath, cfg.privPath);
        else if (cmd == "sign") PQC_App::Sign(cfg.privPath, cfg.inMode, cfg.inValue, cfg.outPath, cfg.encodeFormat);
        else if (cmd == "verify") PQC_App::Verify(cfg.pubPath, cfg.inMode, cfg.inValue, cfg.sigPath, cfg.encodeFormat);
        else if (cmd == "encaps") PQC_App::Encaps(cfg.pubPath, cfg.ctPath, cfg.ssPath, cfg.encodeFormat);
        else if (cmd == "decaps") PQC_App::Decaps(cfg.privPath, cfg.ctPath, cfg.ssPath, cfg.encodeFormat);
        else if (cmd == "issue-cert") PQC_App::IssueCert(cfg.subject, cfg.pubPath, cfg.privPath, cfg.outPath);
        else if (cmd == "verify-cert") PQC_App::VerifyCert(cfg.certPath, cfg.pubPath);
        else if (cmd == "run-tests") PQC_App::RunTests();
        else throw std::invalid_argument("Unknown command mode.");
        
    } catch (const std::exception& e) {
        std::cerr << "[!] CRITICAL ERROR: " << e.what() << "\n";
        return 1;
    }

    return 0;
}