#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <string_view>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>

// ---------------------------------------------------------
// MACROS FOR DLL/SO EXPORT (CROSS-PLATFORM)
// ---------------------------------------------------------
#ifdef _WIN32
  #ifdef HASHTOOL_BUILD_DLL
    #define HASH_API extern "C" __declspec(dllexport)
  #elif defined(HASHTOOL_USE_DLL)
    #define HASH_API extern "C" __declspec(dllimport)
  #else
    #define HASH_API extern "C"
  #endif
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define HASH_API extern "C" __attribute__((visibility("default")))
  #else
    #define HASH_API extern "C"
  #endif
#endif

// =========================================================
// C API ERROR CODES
// =========================================================
#define HASH_SUCCESS 0
#define HASH_ERR_NULL_PTR -1
#define HASH_ERR_BUFFER_TOO_SMALL -2
#define HASH_ERR_EXCEPTION -3

// ========================
// Utility: Encodings
// ========================
std::string to_hex(const std::vector<unsigned char>& data) {
    std::string hex_str;
    hex_str.reserve(data.size() * 2);
    char buf[3];
    for (unsigned char c : data) {
        snprintf(buf, sizeof(buf), "%02x", c);
        hex_str += buf;
    }
    return hex_str;
}

std::string to_base64(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> b64(data.size() * 2 + 1);
    int len = EVP_EncodeBlock(b64.data(), data.data(), data.size());
    return std::string(b64.begin(), b64.begin() + len);
}

// ========================
// Hash Class (Core Logic)
// ========================
class Hasher {
private:
    const EVP_MD* md;
    bool is_xof;

public:
    explicit Hasher(const std::string& algo) {
        OpenSSL_add_all_digests();
        md = EVP_get_digestbyname(algo.c_str());
        if (!md) {
            throw std::runtime_error("Unsupported hash algorithm: " + algo);
        }
        is_xof = (algo == "shake128" || algo == "shake256");
    }

    std::vector<unsigned char> process(const unsigned char* data, size_t len, 
                                       const std::string& filepath, 
                                       size_t xof_outlen = 0) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("DigestInit failed");
        }

        if (!filepath.empty()) {
            std::ifstream file(filepath, std::ios::binary);
            if (!file) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("Cannot open file: " + filepath);
            }
            const size_t buffer_size = 8192;
            char buffer[buffer_size];
            while (file.good()) {
                file.read(buffer, buffer_size);
                std::streamsize bytes = file.gcount();
                if (bytes > 0 && EVP_DigestUpdate(ctx, buffer, bytes) != 1) {
                    EVP_MD_CTX_free(ctx);
                    throw std::runtime_error("DigestUpdate failed during file read");
                }
            }
        } else if (data && len > 0) {
            if (EVP_DigestUpdate(ctx, data, len) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("DigestUpdate failed");
            }
        }

        size_t final_len = is_xof ? (xof_outlen > 0 ? xof_outlen : 32) : (size_t)EVP_MD_size(md);
        std::vector<unsigned char> digest(final_len);

        if (is_xof) {
            if (EVP_DigestFinalXOF(ctx, digest.data(), final_len) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("DigestFinalXOF failed");
            }
        } else {
            unsigned int temp_len = 0;
            if (EVP_DigestFinal_ex(ctx, digest.data(), &temp_len) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("DigestFinal failed");
            }
            digest.resize(temp_len);
        }

        EVP_MD_CTX_free(ctx);
        return digest;
    }
};

// ========================
// DLL Export API (For GUI)
// ========================
HASH_API int hash_buffer_api(const char* algo, const unsigned char* data, size_t len, 
                             unsigned char* out_digest, size_t* out_len, size_t xof_outlen) {
    if (!algo || (!data && len > 0) || !out_digest || !out_len) return HASH_ERR_NULL_PTR;
    try {
        Hasher hasher(algo);
        auto digest = hasher.process(data, len, "", xof_outlen);
        
        if (*out_len < digest.size()) {
            *out_len = digest.size();
            return HASH_ERR_BUFFER_TOO_SMALL; 
        }
        std::memcpy(out_digest, digest.data(), digest.size());
        *out_len = digest.size();
        return HASH_SUCCESS;
    } catch (...) {
        return HASH_ERR_EXCEPTION;
    }
}

HASH_API int hash_file_api(const char* algo, const char* filepath, 
                           unsigned char* out_digest, size_t* out_len, size_t xof_outlen) {
    if (!algo || !filepath || !out_digest || !out_len) return HASH_ERR_NULL_PTR;
    try {
        Hasher hasher(algo);
        auto digest = hasher.process(nullptr, 0, filepath, xof_outlen);
        
        if (*out_len < digest.size()) {
            *out_len = digest.size();
            return HASH_ERR_BUFFER_TOO_SMALL;
        }
        std::memcpy(out_digest, digest.data(), digest.size());
        *out_len = digest.size();
        return HASH_SUCCESS;
    } catch (...) {
        return HASH_ERR_EXCEPTION;
    }
}

// ============================================================================
// COMMAND LINE INTERFACE & KAT RUNNER (UNIFIED ARCHITECTURE)
// ============================================================================
#ifndef HASHTOOL_NO_MAIN // Đổi thành HASHTOOL_NO_MAIN cho đồng bộ

#include <chrono>
#include <map>
#include <set>
#include <algorithm>
#include <cctype>

namespace util {
    enum class OutputFormat { BINARY, HEX, BASE64 };
    enum class InputMode { TEXT, FILE };

    std::string ToUpper(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        return s;
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

    // Tiện ích giải mã Hex (rất cần cho NIST KAT Hash Vectors vì message thường ở dạng hex)
    std::vector<uint8_t> HexDecodeBytes(const std::string& hex) {
        std::vector<uint8_t> decoded;
        if (hex.empty()) return decoded;
        
        auto isHex = [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); };
        auto hexVal = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            return 0;
        };

        std::string cleanHex;
        cleanHex.reserve(hex.size());
        for (char c : hex) { if (isHex(c)) cleanHex.push_back(c); }

        if (cleanHex.size() % 2 != 0) throw std::invalid_argument("Hex format error: odd digits.");
        decoded.reserve(cleanHex.size() / 2);
        for (size_t i = 0; i < cleanHex.size(); i += 2) {
            decoded.push_back((hexVal(cleanHex[i]) << 4) | hexVal(cleanHex[i + 1]));
        }
        return decoded;
    }
}

// --- 1. ĐỒNG NHẤT CẤU TRÚC CONFIG (Dành riêng cho Lab 4 - Hashing) ---
struct CryptoConfig {
    std::string algo;
    util::InputMode inMode;
    std::string inValue;
    std::string outFile;
    util::OutputFormat outFormat;
    size_t outlen = 0;
    bool isStream = false;
    bool isVerbose = false;
};

// --- 2. ĐỒNG NHẤT KAT RUNNER (State-Machine) ---
namespace kat {
    int Run(const std::string& katFile) {
        std::string json;
        try {
            json = util::ReadFileBinary(katFile);
        } catch (const std::exception& e) {
            std::cerr << "[!] Fail Closed (File Error): " << e.what() << "\n";
            return 1;
        }

        std::cout << "=================================================\n";
        std::cout << "  RUNNING KNOWN ANSWER TESTS (HASHING)\n";
        std::cout << "  Source: " << katFile << "\n";
        std::cout << "=================================================\n";

        size_t pos = 0;
        int passed = 0, failed = 0, total = 0;

        
        while ((pos = json.find("\"algo\"", pos)) != std::string::npos) {
            total++;
            size_t currentTcPos = pos;
            pos += 6; 

        
            size_t nextTcPos = json.find("\"algo\"", pos);
            size_t searchEnd = (nextTcPos != std::string::npos) ? nextTcPos : json.length();

          
            auto extractValue = [&](const std::string& key, size_t startPos) -> std::string {
                std::string searchKey = "\"" + key + "\"";
                size_t keyPos = json.find(searchKey, startPos);
                
              
                if (keyPos == std::string::npos || keyPos > searchEnd) return "";

                size_t colonPos = json.find(":", keyPos + searchKey.length());
                if (colonPos == std::string::npos || colonPos > searchEnd) return "";

                size_t start = colonPos + 1;
                while (start < searchEnd && std::isspace(json[start])) start++;
                if (start >= searchEnd) return "";

                
                if (json[start] == '"') {
                    size_t end = json.find("\"", start + 1);
                    if (end == std::string::npos || end > searchEnd) return "";
                    return json.substr(start + 1, end - start - 1);
                } 
               
                else {
                    size_t end = start;
                    while (end < searchEnd && (std::isdigit(json[end]) || json[end] == '-')) end++;
                    return json.substr(start, end - start);
                }
            };

            
            std::string tcIdStr = std::to_string(total);
            std::string parsedTcId = extractValue("tcId", currentTcPos);
            if (!parsedTcId.empty()) {
                tcIdStr = parsedTcId;
            }

            std::string algoStr = extractValue("algo", currentTcPos);
            std::string msgHex = extractValue("msg", currentTcPos);
            std::string expectedMdHex = util::ToLower(extractValue("md", currentTcPos));
            std::string outlenStr = extractValue("outlen", currentTcPos);

            if (algoStr.empty() || msgHex.empty() || expectedMdHex.empty()) {
                continue; 
            }

            std::string algo = util::ToLower(algoStr);
            size_t outlen = outlenStr.empty() ? 0 : std::stoull(outlenStr);
            bool testPassed = false;
            std::string actualMdHex = "";
            std::string errorMsg = "";

            try {
                std::vector<uint8_t> msgBytes = util::HexDecodeBytes(msgHex);
                Hasher hasher(algo);
                auto digest = hasher.process(msgBytes.data(), msgBytes.size(), "", outlen);
                actualMdHex = util::ToLower(to_hex(digest));

                if (actualMdHex == expectedMdHex) {
                    testPassed = true;
                } else {
                    errorMsg = "Digest mismatch";
                }
            } catch (const std::exception& e) {
                errorMsg = std::string("Exception: ") + e.what();
            }

            if (testPassed) {
                std::cout << "  [+] Test " << tcIdStr << " [" << util::ToUpper(algo) << "]: PASS\n";
                passed++;
            } else {
                std::cout << "  [-] Test " << tcIdStr << " [" << util::ToUpper(algo) << "]: FAIL - " << errorMsg << "\n";
                std::cout << "      Expected: " << expectedMdHex << "\n";
                if (!actualMdHex.empty()) {
                    std::cout << "      Actual  : " << actualMdHex << "\n";
                }
                failed++;
            }
        }

        std::cout << "-------------------------------------------------\n";
        std::cout << "Summary: Total Tested: " << total << " | Passed: " << passed << " | Failed: " << failed << "\n";
        if (failed == 0 && total > 0) std::cout << ">>> ALL KATs PASSED SUCCESSFULLY. <<<\n";
        return failed > 0 ? 1 : 0;
    }
}

// --- 3. ĐỒNG NHẤT CLI PARSER (Bảo vệ đầu vào) ---
void PrintUsage(const char* prog) {
    std::cerr
        << "Usage:\n"
        << "  " << prog << " --algo <algo> [--in <file> | --text \"...\"] [--out <file>] [options...]\n"
        << "  " << prog << " --kat <path/to/vectors.json>\n\n"
        << "Run '" << prog << " --help' for full options.\n";
}

void PrintHelp(const char* prog) {
    std::cerr << "=========================================================\n";
    std::cerr << "         HASHTOOL - Multi-algorithm Hash Utility         \n";
    std::cerr << "=========================================================\n\n";
    PrintUsage(prog);
    std::cerr
        << "\nCORE OPTIONS:\n"
        << "  --algo <algo>      sha224 | sha256 | sha384 | sha512 | sha3-224 | sha3-256 | shake128 | shake256\n"
        << "  --in <path>        Input file (Binary-safe).\n"
        << "  --text <string>    Input plain text directly (UTF-8).\n"
        << "  --out <path>       Output file. Screen output if omitted.\n"
        << "\nFORMAT & ENCODING:\n"
        << "  --encode <fmt>     hex | base64 | raw (Default screen: hex, file: raw)\n"
        << "  --outlen <bytes>   Output length in bytes (REQUIRED for SHAKE128/256).\n"
        << "\nMISC:\n"
        << "  --stream           Force logged streaming mode for large files.\n"
        << "  --verbose          Enable detailed execution logs & performance benchmark.\n"
        << "  --kat <path>       Run NIST Known Answer Tests from JSON.\n"
        << "=========================================================\n";
}

class CliParser {
public:
    static CryptoConfig Parse(int argc, char* argv[]) {
        CryptoConfig cfg;
        std::map<std::string, std::string> args;
        std::set<std::string> flags;

        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--verbose" || arg == "--stream") { flags.insert(arg); continue; }
            
            if (arg.rfind("--", 0) == 0) {
                if (i + 1 >= argc || argv[i+1][0] == '-') throw std::invalid_argument("Fail Closed: Missing value for parameter " + arg);
                if (args.count(arg)) throw std::invalid_argument("Fail Closed: parameter " + arg + " repeat");
                args[arg] = argv[++i];
            } else throw std::invalid_argument("Fail Closed: Invalid parameter " + arg);
        }

        cfg.isVerbose = flags.count("--verbose");
        cfg.isStream = flags.count("--stream");

        if (!args.count("--algo")) throw std::invalid_argument("Fail Closed: --algo is required");
        cfg.algo = util::ToLower(args["--algo"]);

        cfg.outlen = args.count("--outlen") ? std::stoull(args["--outlen"]) : 0;
        if ((cfg.algo == "shake128" || cfg.algo == "shake256") && cfg.outlen == 0) {
            throw std::invalid_argument("Fail Closed: SHAKE algorithms require --outlen.");
        }

        bool hasIn = args.count("--in"), hasText = args.count("--text");
        if (hasIn == hasText) throw std::invalid_argument("Fail Closed: Only one input is required (--in OR --text).");
        
        cfg.inMode = hasText ? util::InputMode::TEXT : util::InputMode::FILE;
        cfg.inValue = hasText ? args["--text"] : args["--in"];
        cfg.outFile = args.count("--out") ? args["--out"] : "";

        cfg.outFormat = cfg.outFile.empty() ? util::OutputFormat::HEX : util::OutputFormat::BINARY;
        if (args.count("--encode") && !util::ParseEncodeFormat(args["--encode"], cfg.outFormat)) {
            throw std::invalid_argument("Fail Closed: --encode invalid (hex, base64, raw).");
        }

        return cfg;
    }
};

// --- 4. HÀM MAIN SẠCH SẼ VÀ CỨNG CÁP ---
int main(int argc, char* argv[]) {
    if (argc < 2) { PrintUsage(argv[0]); return 1; }

    std::string first_arg = argv[1];
    if (first_arg == "--help" || first_arg == "-h") { PrintHelp(argv[0]); return 0; }
    if (first_arg == "--kat") {
        if (argc < 3) { std::cerr << "[!] Fail Closed: Missing path for --kat.\n"; return 1; }
        return kat::Run(argv[2]);
    }

    try {
        CryptoConfig cfg = CliParser::Parse(argc, argv);
        Hasher hasher(cfg.algo);
        
        std::vector<unsigned char> digest;
        auto start_time = std::chrono::high_resolution_clock::now();

        if (cfg.inMode == util::InputMode::TEXT) {
            if (cfg.isVerbose) std::cout << "[INFO] Processing Text Buffer...\n";
            digest = hasher.process(reinterpret_cast<const unsigned char*>(cfg.inValue.data()), cfg.inValue.size(), "", cfg.outlen);
        } else {
            if (cfg.isVerbose || cfg.isStream) std::cout << "[INFO] Streaming File: " << cfg.inValue << " (Chunk size: 8192 bytes)\n";
            digest = hasher.process(nullptr, 0, cfg.inValue, cfg.outlen);
        }

        auto end_time = std::chrono::high_resolution_clock::now();

        if (cfg.isVerbose) {
            std::chrono::duration<double> elapsed = end_time - start_time;
            std::cout << "[INFO] Algorithm: " << util::ToUpper(cfg.algo) << " | Execution Time: " << std::fixed << std::setprecision(6) << elapsed.count() << "s\n";
        }

        if (cfg.outFile.empty()) {
            if (cfg.outFormat == util::OutputFormat::HEX) std::cout << to_hex(digest) << "\n";
            else if (cfg.outFormat == util::OutputFormat::BASE64) std::cout << to_base64(digest) << "\n";
            else throw std::runtime_error("Fail Closed: Printing raw binary to the screen is very dangerous. Please use --encode hex or base64");
        } else {
            std::ofstream out(cfg.outFile, std::ios::binary);
            if (!out) throw std::runtime_error("Fail Closed: Can't write file output: " + cfg.outFile);

            if (cfg.outFormat == util::OutputFormat::BINARY) {
                out.write(reinterpret_cast<const char*>(digest.data()), digest.size());
            } else if (cfg.outFormat == util::OutputFormat::HEX) {
                std::string hex_out = to_hex(digest);
                out.write(hex_out.c_str(), hex_out.size());
            } else if (cfg.outFormat == util::OutputFormat::BASE64) {
                std::string b64_out = to_base64(digest);
                out.write(b64_out.c_str(), b64_out.size());
            }
            std::cout << "[+] Hash successful. Output saved to " << cfg.outFile << "\n";
        }

    } 
    catch (const std::exception& e) {
        std::cerr << "[!] CRITICAL ERROR: " << e.what() << "\n";
        return 1; 
    }
    return 0;
}
#endif  