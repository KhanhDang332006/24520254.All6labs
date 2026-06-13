#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>
#include <chrono>
#include <set>
#include <cstdlib> 
#include <cstdio>         
#include <unordered_set>

// ---------------------------------------------------------
// MACROS FOR DLL/SO EXPORT (CROSS-PLATFORM)
// ---------------------------------------------------------
#ifdef _WIN32
  #ifdef AES_PURE_BUILD_DLL
    #define AES_PURE_API extern "C" __declspec(dllexport)
  #elif defined(AES_PURE_USE_DLL)
    #define AES_PURE_API extern "C" __declspec(dllimport)
  #else
    #define AES_PURE_API extern "C"
  #endif
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define AES_PURE_API extern "C" __attribute__((visibility("default")))
  #else
    #define AES_PURE_API extern "C"
  #endif
#endif

// =========================================================
// C API ERROR CODES
// =========================================================
#define AES_SUCCESS 0
#define AES_ERR_NULL_PTR -1
#define AES_ERR_INVALID_KEY_LEN -2
#define AES_ERR_INVALID_IV_LEN -3
#define AES_ERR_EXCEPTION -4

// =========================================================
// C API DECLARATIONS
// =========================================================
AES_PURE_API int api_aes_ctr_encrypt(const uint8_t* in_data, size_t in_len, 
                            const uint8_t* key, size_t key_len, 
                            const uint8_t* iv, size_t iv_len, 
                            uint8_t* out_data);

AES_PURE_API int api_aes_ctr_decrypt(const uint8_t* in_data, size_t in_len, 
                            const uint8_t* key, size_t key_len, 
                            const uint8_t* iv, size_t iv_len, 
                            uint8_t* out_data);


AES_PURE_API void free_memory(void* p) noexcept;


// =========================================================
// CORE AES IMPLEMENTATION
// =========================================================
namespace aes {

    inline void SecureWipe(void* v, size_t n) {
        if (!v || n == 0) return;
        volatile uint8_t* p = static_cast<volatile uint8_t*>(v);
        while (n--) *p++ = 0;
    }

    constexpr size_t AES128_KEY_LEN = 16;
    constexpr size_t AES_BLOCK_SIZE = 16;
    constexpr size_t EXPANDED_KEY_SIZE = 176;

    static const uint8_t sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    static const uint8_t rcon[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    inline uint8_t xtime(uint8_t x) {
        return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
    }

    void KeyExpansion(const uint8_t* key, uint8_t* expKey) {
        for (int i = 0; i < 16; i++) {
            expKey[i] = key[i];
        }
        size_t bytesGenerated = 16;
        int rconIter = 1;
        uint8_t temp[4];

        while (bytesGenerated < EXPANDED_KEY_SIZE) {
            for (int i = 0; i < 4; i++) temp[i] = expKey[bytesGenerated - 4 + i];

            if (bytesGenerated % 16 == 0) {
                uint8_t t = temp[0]; 
                temp[0] = temp[1]; 
                temp[1] = temp[2]; 
                temp[2] = temp[3]; 
                temp[3] = t;

                for (int i = 0; i < 4; i++) temp[i] = sbox[temp[i]];

                temp[0] ^= rcon[rconIter++];
            }

            for (int i = 0; i < 4; i++) {
                expKey[bytesGenerated] = expKey[bytesGenerated - 16] ^ temp[i];
                bytesGenerated++;
            }
        }
        SecureWipe(temp, sizeof(temp));
    }

    void CipherBlock(const uint8_t* expKey, uint8_t* state) {
        auto AddRoundKey = [](uint8_t* st, const uint8_t* rk) {
            for (int i = 0; i < 16; ++i) st[i] ^= rk[i];
        };

        auto SubBytes = [](uint8_t* st) {
            for (int i = 0; i < 16; i++) st[i] = sbox[st[i]];
        };

        auto ShiftRows = [](uint8_t* st) {
            uint8_t temp;
            temp = st[1]; st[1] = st[5]; st[5] = st[9]; st[9] = st[13]; st[13] = temp;
            temp = st[2]; st[2] = st[10]; st[10] = temp;
            temp = st[6]; st[6] = st[14]; st[14] = temp;
            temp = st[15]; st[15] = st[11]; st[11] = st[7]; st[7] = st[3]; st[3] = temp;
        };

        auto MixColumns = [](uint8_t* st) {
            for (int c = 0; c < 4; c++) {
                int i = c * 4;
                uint8_t t = st[i];
                uint8_t tmp = st[i] ^ st[i + 1] ^ st[i + 2] ^ st[i + 3];
                uint8_t tm;
                tm = st[i] ^ st[i + 1]; tm = xtime(tm); st[i] ^= tm ^ tmp;
                tm = st[i + 1] ^ st[i + 2]; tm = xtime(tm); st[i + 1] ^= tm ^ tmp;
                tm = st[i + 2] ^ st[i + 3]; tm = xtime(tm); st[i + 2] ^= tm ^ tmp;
                tm = st[i + 3] ^ t; tm = xtime(tm); st[i + 3] ^= tm ^ tmp;
            }
        };

        AddRoundKey(state, expKey);

        for (int round = 1; round < 10; ++round) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, expKey + round * 16);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, expKey + 10 * 16);
    }

    // [DOCUMENTATION]
    // Counter endianness: Big-Endian byte order. The increment starts at the last byte (index 15) 
    // which acts as the Least Significant Byte (LSB).
    // Counter overflow behavior: When a byte overflows (0xFF -> 0x00), the carry is propagated 
    // to the next most significant byte (index - 1). If the entire 128-bit block overflows 
    // (all 0xFFs), it safely wraps around to all zeros.
    void IncrementCounter(std::array<uint8_t, 16>& counter) {
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
    }
}

// =========================================================
// C API DEFINITIONS
// =========================================================

AES_PURE_API void free_memory(void* p) noexcept {
    std::free(p);
}

AES_PURE_API int aes_ctr_encrypt(const uint8_t* in_data, size_t in_len, 
                            const uint8_t* key, size_t key_len, 
                            const uint8_t* iv, size_t iv_len, 
                            uint8_t* out_data) {
    
    if (in_len == 0) return AES_SUCCESS; 
    if (!in_data || !out_data || !key || !iv) return AES_ERR_NULL_PTR;
    if (key_len != aes::AES128_KEY_LEN) return AES_ERR_INVALID_KEY_LEN;
    if (iv_len != aes::AES_BLOCK_SIZE) return AES_ERR_INVALID_IV_LEN;

    try {
        uint8_t expKey[aes::EXPANDED_KEY_SIZE];
        aes::KeyExpansion(key, expKey);

        std::array<uint8_t, 16> counterBlock;
        std::copy(iv, iv + 16, counterBlock.begin());

        size_t offset = 0;
        uint8_t keystream[16];

        while (offset < in_len) {
            std::copy(counterBlock.begin(), counterBlock.end(), keystream);
            aes::CipherBlock(expKey, keystream);

            size_t blockLen = std::min<size_t>(16, in_len - offset);
            for (size_t i = 0; i < blockLen; ++i) {
                out_data[offset + i] = in_data[offset + i] ^ keystream[i];
            }
            offset += blockLen;
            aes::IncrementCounter(counterBlock);
        }

        aes::SecureWipe(expKey, sizeof(expKey));
        aes::SecureWipe(keystream, sizeof(keystream));
        aes::SecureWipe(counterBlock.data(), counterBlock.size());

        return AES_SUCCESS;
    } catch (...) {
        return AES_ERR_EXCEPTION;
    }
}

AES_PURE_API int aes_ctr_decrypt(const uint8_t* in_data, size_t in_len, 
                            const uint8_t* key, size_t key_len, 
                            const uint8_t* iv, size_t iv_len, 
                            uint8_t* out_data) {
    return aes_ctr_encrypt(in_data, in_len, key, key_len, iv, iv_len, out_data);
}


// ============================================================================
// COMMAND LINE INTERFACE & KAT RUNNER (UNIFIED ARCHITECTURE)
// ============================================================================
#ifndef LIB_EXPORTS

#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <set>
#include <chrono>

#if defined(_WIN32)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <bcrypt.h>
#else
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #if defined(__linux__)
        #include <sys/random.h>
    #endif
#endif

namespace util {

    enum class OutputFormat { BINARY, HEX, BASE64 };
    enum class InputMode { TEXT, FILE };

    template <typename T>
    struct SecureVector : public std::vector<T> {
        using std::vector<T>::vector;
        ~SecureVector() { if (!this->empty()) aes::SecureWipe(this->data(), this->size() * sizeof(T)); }
    };

    void GenerateSecureRandom(uint8_t* buffer, size_t len) {
        if (!buffer || len == 0) return;
#if defined(_WIN32)
        if (BCryptGenRandom(NULL, buffer, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            throw std::runtime_error("BCryptGenRandom failed to generate secure bytes.");
        }
#else
        size_t total_read = 0;
#if defined(__linux__)
        while (total_read < len) {
            ssize_t ret = getrandom(buffer + total_read, len - total_read, 0);
            if (ret < 0) {
                if (errno == EINTR) continue;
                break; // Fallback to /dev/urandom
            }
            total_read += ret;
        }
#endif
        if (total_read < len) {
            int fd = open("/dev/urandom", O_RDONLY);
            if (fd < 0) throw std::runtime_error("Failed to open /dev/urandom");
            while (total_read < len) {
                ssize_t ret = read(fd, buffer + total_read, len - total_read);
                if (ret < 0) {
                    if (errno == EINTR) continue;
                    close(fd);
                    throw std::runtime_error("Failed to read from /dev/urandom");
                }
                total_read += ret;
            }
            close(fd);
        }
#endif
    }

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

    std::string HexEncode(const std::string& data) {
        if (data.empty()) return "";
        return HexEncode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }

    std::vector<uint8_t> HexDecodeBytes(const std::string& hex) {
        std::vector<uint8_t> decoded;
        if (hex.empty()) return decoded;
        
        auto isHex = [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        };

        auto hexVal = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            return 0;
        };

        std::string cleanHex;
        cleanHex.reserve(hex.size());
        for (char c : hex) {
            if (isHex(c)) cleanHex.push_back(c);
        }

        if (cleanHex.size() % 2 != 0) {
            throw std::invalid_argument("Hex string format error: odd number of valid digits.");
        }

        decoded.reserve(cleanHex.size() / 2);
        for (size_t i = 0; i < cleanHex.size(); i += 2) {
            decoded.push_back((hexVal(cleanHex[i]) << 4) | hexVal(cleanHex[i + 1]));
        }
        return decoded;
    }

    std::string HexDecode(const std::string& hex) {
        auto dec = HexDecodeBytes(hex);
        if (dec.empty()) return "";
        return std::string(dec.begin(), dec.end());
    }

    std::string Base64Encode(const std::string& data) {
        if (data.empty()) return "";
        static const char b64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(((data.size() + 2) / 3) * 4);
        int val = 0;
        int valb = -6;
        for (unsigned char c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(b64Chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) {
            out.push_back(b64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        while (out.size() % 4) {
            out.push_back('=');
        }
        return out;
    }

    std::string Base64Decode(const std::string& input) {
        if (input.empty()) return "";
        static const int T[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
            -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
        };
        std::string out;
        out.reserve(input.size() * 3 / 4);
        int val = 0, valb = -8;
        for (unsigned char c : input) {
            if (c == '=') break;
            if (T[c] == -1) continue; 
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                out.push_back(static_cast<char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }

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

    void WriteFileBinary(const std::string& filename, const std::string& content) {
        std::ofstream out(filename, std::ios::binary);
        if (!out) throw std::runtime_error("Failed to open file for writing: " + filename);
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!out) throw std::runtime_error("Failed to write file: " + filename);
    }

    bool IsHexString(const std::string& str) {
        if (str.empty()) return false;
        for (char c : str) {
            if (!std::isxdigit(static_cast<unsigned char>(c)) && !std::isspace(static_cast<unsigned char>(c))) return false;
        }
        return true;
    }

    std::string ProcessCTRCli(const std::string& input, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, bool isEncrypt) {
        if (input.empty()) return "";
        std::string output;
        output.resize(input.size());

        int status = isEncrypt ? 
            aes_ctr_encrypt(
                reinterpret_cast<const uint8_t*>(input.data()), input.size(),
                key.data(), key.size(),
                iv.data(), iv.size(),
                reinterpret_cast<uint8_t*>(&output[0])
            ) :
            aes_ctr_decrypt(
                reinterpret_cast<const uint8_t*>(input.data()), input.size(),
                key.data(), key.size(),
                iv.data(), iv.size(),
                reinterpret_cast<uint8_t*>(&output[0])
            );

        if (status != AES_SUCCESS) {
            throw std::runtime_error("AES C API returned error code: " + std::to_string(status));
        }
        return output;
    }

    // ============================================================================
    // NONCE TRACKER (Tối ưu cache O(1) trên RAM)
    // ============================================================================
    struct NonceTracker {
        static std::string ComputeSecureID(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
            if (key.size() != 16 || iv.size() != 16) return "";
            uint8_t expKey[176];
            aes::KeyExpansion(key.data(), expKey);
            
            uint8_t trackingKey[16] = {'N','O','N','C','E','_','T','R','A','C','K','E','R','_','I','D'};
            aes::CipherBlock(expKey, trackingKey); 

            uint8_t expTrackingKey[176];
            aes::KeyExpansion(trackingKey, expTrackingKey);
            
            uint8_t secureID[16];
            std::memcpy(secureID, iv.data(), 16);
            aes::CipherBlock(expTrackingKey, secureID);

            aes::SecureWipe(expKey, sizeof(expKey));
            aes::SecureWipe(trackingKey, sizeof(trackingKey));
            aes::SecureWipe(expTrackingKey, sizeof(expTrackingKey));
            return HexEncode(secureID, 16);
        }

        static void CheckAndRegister(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
            static std::unordered_set<std::string> cache;
            static bool loaded = false;
            std::string dbPath = ".nonce_db";

            // Nạp DB lên RAM một lần duy nhất lúc khởi động
            if (!loaded) {
                std::ifstream inFile(dbPath);
                if (inFile.is_open()) {
                    std::string line;
                    while (std::getline(inFile, line)) cache.insert(line);
                    inFile.close();
                }
                loaded = true;
            }

            std::string record = ComputeSecureID(key, iv);
            if (cache.count(record)) {
                throw std::runtime_error(
                    "\n[CATASTROPHIC ERROR] Nonce reuse detected for this Key!\n"
                    "Operation rejected to prevent Keystream Reuse attack (C1 ^ C2 = P1 ^ P2).\n"
                    "Please use a unique IV/Nonce."
                );
            }

            cache.insert(record);
            std::ofstream outFile(dbPath, std::ios::app);
            if (!outFile) throw std::runtime_error("Cannot open .nonce_db to track IV.");
            outFile << record << "\n";
            outFile.close();
        }
    };

    // ============================================================================
    // STREAMING I/O (Xử lý Chunking 64KB cho file 1 GiB)
    // ============================================================================
    void ProcessCTRFileChunked(const std::string& inPath, const std::string& outPath, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
        std::ifstream in(inPath, std::ios::binary);
        if (!in) throw std::runtime_error("Cannot open input file for chunking: " + inPath);
        std::ofstream out(outPath, std::ios::binary);
        if (!out) throw std::runtime_error("Cannot open output file for chunking: " + outPath);

        uint8_t expKey[aes::EXPANDED_KEY_SIZE];
        aes::KeyExpansion(key.data(), expKey);

        std::array<uint8_t, 16> counterBlock;
        std::copy(iv.begin(), iv.end(), counterBlock.begin());

        const size_t CHUNK_SIZE = 65536; // Cắt lát 64KB để không tràn RAM
        std::vector<uint8_t> buffer(CHUNK_SIZE);
        uint8_t keystream[16];

        while (in) {
            in.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
            size_t bytesRead = in.gcount();
            if (bytesRead == 0) break;

            size_t offset = 0;
            while (offset < bytesRead) {
                std::copy(counterBlock.begin(), counterBlock.end(), keystream);
                aes::CipherBlock(expKey, keystream);

                size_t blockLen = std::min<size_t>(16, bytesRead - offset);
                for (size_t i = 0; i < blockLen; ++i) {
                    buffer[offset + i] ^= keystream[i];
                }
                offset += blockLen;
                aes::IncrementCounter(counterBlock);
            }
            out.write(reinterpret_cast<const char*>(buffer.data()), bytesRead);
        }

        // Xóa sạch dấu vết mật mã trên RAM
        aes::SecureWipe(expKey, sizeof(expKey));
        aes::SecureWipe(keystream, sizeof(keystream));
        aes::SecureWipe(counterBlock.data(), counterBlock.size());
        aes::SecureWipe(buffer.data(), buffer.size());
    }

} // namespace util


struct CryptoConfig {
    bool isEncrypt;
    std::string mode;
    std::vector<uint8_t> keyRaw;
    util::InputMode inMode;
    std::string inValue;
    std::string outFile;
    util::OutputFormat outFormat;
    bool isVerbose = false;
    std::vector<uint8_t> explicitIvRaw;
};

// --- 2. ĐỒNG NHẤT KAT RUNNER (Dùng State-Machine an toàn) ---
namespace kat {
    static std::vector<std::map<std::string, std::string>> ParseSimpleJsonArray(const std::string& filepath) {
        std::vector<std::map<std::string, std::string>> array;
        std::string content = util::ReadFileBinary(filepath);
        std::map<std::string, std::string> currentObj;
        bool inString = false;
        std::string currentKey = "", currentVal = "", token = "";
        bool expectingVal = false;
        
        for (size_t i = 0; i < content.size(); ++i) {
            char c = content[i];
            if (c == '"') {
                inString = !inString;
                if (!inString) { 
                    if (!expectingVal) currentKey = token;
                    else {
                        currentVal = token;
                        currentObj[util::ToUpper(currentKey)] = currentVal; 
                        currentKey.clear(); currentVal.clear(); expectingVal = false;
                    }
                    token.clear();
                }
                continue;
            }
            if (inString) token += c;
            else {
                if (c == '{') currentObj.clear();
                else if (c == '}') { if (!currentObj.empty()) array.push_back(currentObj); currentObj.clear(); }
                else if (c == ':') expectingVal = true;
            }
        }
        return array;
    }

    int Run(const std::string& filepath) {
        std::vector<std::map<std::string, std::string>> kats;
        try { kats = ParseSimpleJsonArray(filepath); } 
        catch (const std::exception& e) {
            std::cerr << "[!] Fail Closed (JSON Error): " << e.what() << "\n"; return 1;
        }

        int passed = 0, failed = 0;
        std::cout << "=================================================\n";
        std::cout << "  RUNNING KNOWN ANSWER TESTS (NIST KATs - CTR)\n";
        std::cout << "=================================================\n";

        for (const auto& tc : kats) {
            try {
                std::string id = tc.count("ID") ? tc.at("ID") : (tc.count("COUNT") ? tc.at("COUNT") : "Unknown");
                if (!tc.count("KEY") || !tc.count("IV") || (!tc.count("PLAINTEXT") && !tc.count("PT")) || (!tc.count("CIPHERTEXT") && !tc.count("CT"))) continue;

                auto key = util::HexDecodeBytes(tc.at("KEY"));
                auto iv = util::HexDecodeBytes(tc.at("IV"));
                auto ptStr = tc.count("PLAINTEXT") ? util::HexDecode(tc.at("PLAINTEXT")) : util::HexDecode(tc.at("PT"));
                auto expectedCtStr = tc.count("CIPHERTEXT") ? util::HexDecode(tc.at("CIPHERTEXT")) : util::HexDecode(tc.at("CT"));

                std::string actualCtStr = util::ProcessCTRCli(ptStr, key, iv, true);
                
                if (actualCtStr == expectedCtStr) {
                    std::cout << "[PASS] Test ID: " << id << "\n"; passed++;
                } else {
                    std::cout << "[FAIL] Test ID: " << id << " - Ciphertext Mismatch!\n"; failed++;
                }
            } catch (...) { failed++; }
        }
        std::cout << "-------------------------------------------------\n";
        std::cout << "Summary: Total Tested: " << passed + failed << " | Passed: " << passed << " | Failed: " << failed << "\n";
        if (failed == 0 && (passed+failed) > 0) std::cout << ">>> ALL KATs PASSED SUCCESSFULY. <<<\n";
        return failed > 0 ? 1 : 0;
    }
}

void PrintUsage(const char* prog) {
    std::cerr
        << "Usage:\n  " << prog << " keygen --out <keyfile.hex>\n"
        << "  " << prog << " encrypt [--in INFILE | --text \"...\"] [--out OUTFILE] [--key KEYFILE | --key-hex HEX] [--iv IVFILE | --iv-hex HEX] [--mode ctr] [options...]\n"
        << "  " << prog << " decrypt [--in INFILE | --text \"...\"] [--out OUTFILE] [--key KEYFILE | --key-hex HEX] [--iv IVFILE | --iv-hex HEX] [--mode ctr] [options...]\n"
        << "  " << prog << " --kat <path/to/vectors.json>\n\nRun '" << prog << " --help' for full options.\n";
}

void PrintHelp(const char* prog) {
    std::cerr << "=========================================================\n";
    std::cerr << "       AESToolPureC - Symmetric Encryption Utility       \n";
    std::cerr << "=========================================================\n\n";
    PrintUsage(prog);
    std::cerr
        << "\nCORE OPTIONS:\n"
        << "  --mode <mode>      ctr (Only CTR mode is supported in this build)\n"
        << "  --key <path>       Path to AES key file (Raw Binary or Hex).\n"
        << "  --key-hex <hex>    Provide AES key directly as Hex string.\n"
        << "  --iv <path>        Path to IV file (Raw Binary or Hex).\n"
        << "  --iv-hex <hex>     Provide IV directly as Hex string.\n"
        << "  --in <path>        Input file (Binary-safe).\n"
        << "  --text <string>    Input plain text directly (UTF-8).\n"
        << "  --out <path>       Output file (Binary-safe). Screen output if omitted.\n"
        << "\nFORMAT & ENCODING:\n"
        << "  --encode <fmt>     hex | base64 | raw (Default screen: hex, file: raw)\n"
        << "\nMISC:\n"
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
        std::set<std::string> flags;

        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--verbose") { flags.insert(arg); continue; }
            if (arg.rfind("--", 0) == 0) {
                if (i + 1 >= argc || argv[i+1][0] == '-') throw std::invalid_argument("Fail Closed: Thiếu giá trị cho tham số " + arg);
                if (args.count(arg)) throw std::invalid_argument("Fail Closed: Tham số " + arg + " bị lặp lại.");
                args[arg] = argv[++i];
            } else throw std::invalid_argument("Fail Closed: Tham số không hợp lệ " + arg);
        }

        cfg.isVerbose = flags.count("--verbose");

        if (!args.count("--mode")) throw std::invalid_argument("Fail Closed: Bắt buộc phải có --mode ctr.");
        cfg.mode = util::ToLower(args["--mode"]);
        if (cfg.mode != "ctr") throw std::invalid_argument("Fail Closed: Pure C++ Lab chỉ hỗ trợ chế độ CTR.");

        // Key Parse
        if (args.count("--key-hex")) cfg.keyRaw = util::HexDecodeBytes(args["--key-hex"]);
        else if (args.count("--key")) {
            std::string kData = util::ReadFileBinary(args["--key"]);
            std::string kTrim = kData.substr(0, kData.find_last_not_of(" \r\n\t") + 1);
            if (util::IsHexString(kTrim)) cfg.keyRaw = util::HexDecodeBytes(kTrim);
            else cfg.keyRaw.assign(kData.begin(), kData.end());
        } else throw std::invalid_argument("Fail Closed: Thiếu --key hoặc --key-hex.");

        if (args.count("--iv-hex")) cfg.explicitIvRaw = util::HexDecodeBytes(args["--iv-hex"]);
        else if (args.count("--iv")) {
            std::string ivData = util::ReadFileBinary(args["--iv"]);
            std::string ivTrim = ivData.substr(0, ivData.find_last_not_of(" \r\n\t") + 1);
            if (util::IsHexString(ivTrim)) cfg.explicitIvRaw = util::HexDecodeBytes(ivTrim);
            else cfg.explicitIvRaw.assign(ivData.begin(), ivData.end());
        } else throw std::invalid_argument("Fail Closed: Thiếu --iv hoặc --iv-hex.");

        if (cfg.keyRaw.size() != 16 || cfg.explicitIvRaw.size() != 16) {
            throw std::invalid_argument("Fail Closed: AES-128 CTR requires the Key and IV to be exactly 16 bytes long.");
        }

        bool hasIn = args.count("--in"), hasText = args.count("--text");
        if (hasIn == hasText) throw std::invalid_argument("Fail Closed: Phải có đúng một đầu vào (--in HOẶC --text).");
        cfg.inMode = hasText ? util::InputMode::TEXT : util::InputMode::FILE;
        cfg.inValue = hasText ? args["--text"] : args["--in"];
        cfg.outFile = args.count("--out") ? args["--out"] : "";

        cfg.outFormat = cfg.outFile.empty() ? util::OutputFormat::HEX : util::OutputFormat::BINARY;
        if (args.count("--encode") && !util::ParseEncodeFormat(args["--encode"], cfg.outFormat)) {
            throw std::invalid_argument("Fail Closed: --encode không hợp lệ (hex, base64, raw).");
        }
        return cfg;
    }
};

// --- 4. HÀM MAIN SẠCH SẼ VÀ CỨNG CÁP ---
int main(int argc, char* argv[]) {
    if (argc < 2) { PrintUsage(argv[0]); return 1; }
    std::string command = argv[1];

    if (command == "--help" || command == "-h") { PrintHelp(argv[0]); return 0; }
    if (command == "--kat") {
        if (argc < 3) { std::cerr << "[!] Fail Closed: Missing path for --kat.\n"; return 1; }
        return kat::Run(argv[2]);
    }

    std::string activeOutFile = ""; // Biến theo dõi để dọn dẹp khi có sự cố (Fail-Closed)
    
    try {
        if (command == "keygen") {
            // ... (Giữ nguyên logic keygen cũ) ...
            std::string outFile = "";
            for (int i = 2; i < argc; i++) if (std::string(argv[i]) == "--out" && i + 1 < argc) outFile = argv[++i];
            if (outFile.empty()) throw std::invalid_argument("Fail Closed: Missing --out parameter.");
            
            std::vector<uint8_t> key(16);
            util::GenerateSecureRandom(key.data(), key.size());
            util::WriteFileBinary(outFile, util::HexEncode(key.data(), key.size()) + "\n");
            std::cout << "[+] Keygen successful.\n";
            return 0;
        }
        else if (command == "encrypt" || command == "decrypt") {
            CryptoConfig cfg = CliParser::Parse(argc, argv, command);
            activeOutFile = cfg.outFile; // Đánh dấu file đang ghi

            if (cfg.isEncrypt) {
                if (cfg.isVerbose) std::cout << "[INFO] Checking .nonce_db to prevent Keystream Reuse attack...\n";
                util::NonceTracker::CheckAndRegister(cfg.keyRaw, cfg.explicitIvRaw);
            }

            auto start_time = std::chrono::high_resolution_clock::now();

            // ĐỊNH TUYẾN: Dùng Chunking I/O nếu là File-to-File và xuất Binary [cite: 74-75]
            if (cfg.inMode == util::InputMode::FILE && !cfg.outFile.empty() && cfg.outFormat == util::OutputFormat::BINARY) {
                if (cfg.isVerbose) std::cout << "[INFO] Using Chunked I/O for large file processing.\n";
                util::ProcessCTRFileChunked(cfg.inValue, cfg.outFile, cfg.keyRaw, cfg.explicitIvRaw);
                
                auto end_time = std::chrono::high_resolution_clock::now();
                if (cfg.isVerbose) {
                    std::chrono::duration<double> elapsed = end_time - start_time;
                    std::ifstream in(cfg.inValue, std::ios::ate | std::ios::binary);
                    double mb = static_cast<double>(in.tellg()) / (1024.0 * 1024.0);
                    std::cout << "[INFO] Mode: CTR | Execution: " << std::fixed << std::setprecision(6) << elapsed.count() << "s | Throughput: " << (mb / elapsed.count()) << " MB/s\n";
                }
                std::cout << "[+] " << (cfg.isEncrypt ? "Encryption" : "Decryption") << " successful.\n";
            } 
            // ĐỊNH TUYẾN: Dùng Memory I/O cho Text mode hoặc khi cần encode Base64/Hex
            else {
                if (cfg.isVerbose) std::cout << "[INFO] Using In-Memory processing.\n";
                std::string inputData = (cfg.inMode == util::InputMode::TEXT) ? cfg.inValue : util::ReadFileBinary(cfg.inValue);
                std::string resultData = util::ProcessCTRCli(inputData, cfg.keyRaw, cfg.explicitIvRaw, cfg.isEncrypt);
                
                auto end_time = std::chrono::high_resolution_clock::now();
                if (cfg.isVerbose) {
                    std::chrono::duration<double> elapsed = end_time - start_time;
                    double mb = static_cast<double>(inputData.size()) / (1024.0 * 1024.0);
                    std::cout << "[INFO] Mode: CTR | Execution: " << std::fixed << std::setprecision(6) << elapsed.count() << "s | Throughput: " << (mb / elapsed.count()) << " MB/s\n";
                }

                if (!resultData.empty()) {
                    if (cfg.outFormat == util::OutputFormat::BASE64) resultData = util::Base64Encode(resultData);
                    else if (cfg.outFormat == util::OutputFormat::HEX) resultData = util::HexEncode(resultData);
                }

                if (cfg.outFile.empty()) std::cout << resultData << "\n";
                else {
                    util::WriteFileBinary(cfg.outFile, resultData);
                    std::cout << "[+] " << (cfg.isEncrypt ? "Encryption" : "Decryption") << " successful.\n";
                }

                aes::SecureWipe(&inputData[0], inputData.size());
                aes::SecureWipe(&resultData[0], resultData.size());
            }

            activeOutFile = ""; 
            return 0;
        }
        else {
            std::cerr << "Unknown command: " << command << "\n";
            PrintUsage(argv[0]);
            return 1; 
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] CRITICAL ERROR: " << e.what() << "\n";
        if (!activeOutFile.empty()) {
            std::remove(activeOutFile.c_str());
            std::cerr << "[!] Fail-Closed: Removed incomplete/corrupted output file -> " << activeOutFile << "\n";
        }
        return 1;
    }
}
#endif