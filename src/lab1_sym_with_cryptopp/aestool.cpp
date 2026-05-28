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
#include <cryptopp/sha.h>
#include<cryptopp/channels.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <filesystem>
#include <map>
#include <set>
#include <cctype>

using namespace CryptoPP;
namespace fs = std::filesystem;

// =========================================================
// MACROS FOR DLL EXPORT
// =========================================================
#ifdef _WIN32
  #ifdef AESTOOL_BUILD_DLL
    #define AESTOOL_API extern "C" __declspec(dllexport)
  #else
    #define AESTOOL_API extern "C"
  #endif
#else
  #define AESTOOL_API extern "C"
#endif

// =========================================================
// UTILS: HEX ENCODE / DECODE & FILE SIZE
// =========================================================
std::string EncodeHex(const byte* data, size_t len) {
    std::string encoded;
    StringSource(data, len, true, new HexEncoder(new StringSink(encoded), true));
    return encoded;
}

void DecodeHex(const std::string& hex, SecByteBlock& decoded) {
    decoded.CleanNew(hex.length() / 2);
    StringSource(hex, true, new HexDecoder(new ArraySink(decoded, decoded.size())));
}

size_t GetFileSize(const std::string& filename) {
    if (!fs::exists(filename)) return 0;
    return fs::file_size(filename);
}

// =========================================================
// SIDECAR JSON MANAGER
// =========================================================
struct SidecarMeta {
    std::string alg;
    std::string iv_hex;
    std::string aad_hex;
    std::string tag_hex;
};

void SaveSidecar(const std::string& file, const SidecarMeta& meta) {
    std::ofstream out(file);
    out << "{\n";
    out << "  \"alg\": \"" << meta.alg << "\",\n";
    out << "  \"iv\": \"" << meta.iv_hex << "\",\n";
    if (!meta.aad_hex.empty()) out << "  \"aad\": \"" << meta.aad_hex << "\",\n";
    if (!meta.tag_hex.empty()) out << "  \"tag\": \"" << meta.tag_hex << "\"\n";
    out << "}\n";
}

SidecarMeta LoadSidecar(const std::string& file) {
    SidecarMeta meta;
    std::ifstream in(file);
    if (!in) return meta;
    std::string line;
    while (std::getline(in, line)) {
        if (line.find("\"alg\":") != std::string::npos) {
            size_t start = line.find_first_of(':') + 3;
            meta.alg = line.substr(start, line.find_last_of('"') - start);
        }
        else if (line.find("\"iv\":") != std::string::npos) {
            size_t start = line.find_first_of(':') + 3;
            meta.iv_hex = line.substr(start, line.find_last_of('"') - start);
        }
        else if (line.find("\"aad\":") != std::string::npos) {
            size_t start = line.find_first_of(':') + 3;
            meta.aad_hex = line.substr(start, line.find_last_of('"') - start);
        }
        else if (line.find("\"tag\":") != std::string::npos) {
            size_t start = line.find_first_of(':') + 3;
            meta.tag_hex = line.substr(start, line.find_last_of('"') - start);
        }
    }
    return meta;
}

// =========================================================
// MISUSE PREVENTION: NONCE REUSE TRACKER
// =========================================================
struct NonceTracker {
    static std::string HashKeyNonce(const std::string& keyHex, const std::string& nonceHex) {
        SHA256 hash;
        std::string digest;
        StringSource s(keyHex + nonceHex, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
        return digest;
    }

    static void CheckAndRegister(const std::string& mode, const std::string& keyHex, const std::string& nonceHex) {
        if (mode != "ctr" && mode != "gcm" && mode != "ccm") return;

        std::string dbPath = ".nonce_db";
        std::string record = HashKeyNonce(keyHex, nonceHex);

        std::ifstream in(dbPath);
        if (in) {
            std::string line;
            while (std::getline(in, line)) {
                if (line == record) {
                    throw std::runtime_error("CATASTROPHIC ERROR (Misuse Prevention): Nonce reuse detected for this key! Operation rejected to prevent Keystream Reuse attack.");
                }
            }
            in.close();
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
    static void GenerateKey(const std::string& outfile, size_t keyLength = AES::DEFAULT_KEYLENGTH) {
        AutoSeededRandomPool prng;
        SecByteBlock key(keyLength);
        prng.GenerateBlock(key, key.size());

        std::ofstream out(outfile);
        out << EncodeHex(key.data(), key.size()) << "\n";
        std::cout << "[+] Key generated and saved to: " << outfile << "\n";
    }

    template<class ENCRYPTION_MODE>
    static void EncryptStandard(const std::string& in, const std::string& out, const SecByteBlock& key, const SecByteBlock& iv) {
        ENCRYPTION_MODE enc;
        if (iv.size() > 0) enc.SetKeyWithIV(key, key.size(), iv, iv.size());
        else enc.SetKey(key, key.size());

        FileSource fs(in.c_str(), true, new StreamTransformationFilter(enc, new FileSink(out.c_str())));
    }

    template<class DECRYPTION_MODE>
    static void DecryptStandard(const std::string& in, const std::string& out, const SecByteBlock& key, const SecByteBlock& iv) {
        DECRYPTION_MODE dec;
        if (iv.size() > 0) dec.SetKeyWithIV(key, key.size(), iv, iv.size());
        else dec.SetKey(key, key.size());

        FileSource fs(in.c_str(), true, new StreamTransformationFilter(dec, new FileSink(out.c_str())));
    }

template<class AEAD_ENC>
static void EncryptAEAD(
    const std::string& in,
    const std::string& out,
    const SecByteBlock& key,
    const SecByteBlock& iv,
    const std::string& aad,
    std::string& outTagHex)
{
    AEAD_ENC enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    enc.SpecifyDataLengths(aad.size(), GetFileSize(in), 0);

    const int TAG_SIZE = 16;
    SecByteBlock tag(TAG_SIZE);

    // 1. Khai báo các Sink trên Stack (cực kỳ an toàn, tự động dọn rác khi hàm kết thúc)
    FileSink fileSink(out.c_str());
    ArraySink macSink(tag, tag.size());

    // 2. ChannelSwitch nhận tham chiếu (&) của luồng mặc định
    ChannelSwitch cs(fileSink);
    
    // 3. Định tuyến luồng MAC vào macSink
    cs.AddRoute("MAC_CHANNEL", macSink, DEFAULT_CHANNEL);

    // 4. Khởi tạo Filter trên Heap để FileSource tự động quản lý.
    // Dùng Redirector(cs) để làm cầu nối trung gian trỏ vào biến cs trên stack.
    AuthenticatedEncryptionFilter* ef = new AuthenticatedEncryptionFilter(
        enc,
        new Redirector(cs),
        false,        // putAAD = false
        TAG_SIZE,
        "MAC_CHANNEL" // Chỉ định MAC đi vào luồng MAC_CHANNEL
    );

    // Nạp AAD
    if (!aad.empty()) {
        ef->ChannelPut(AAD_CHANNEL, reinterpret_cast<const byte*>(aad.data()), aad.size());
        ef->ChannelMessageEnd(AAD_CHANNEL);
    }

    // Bơm Plaintext (FileSource sẽ tự động delete ef khi xử lý xong)
    FileSource fs(in.c_str(), true, ef);

    // Lúc này macSink đã hứng trọn vẹn 16 bytes MAC thật
    outTagHex = EncodeHex(tag.data(), tag.size());
}

template<class AEAD_DEC>
static void DecryptAEAD(
    const std::string& in,
    const std::string& out,
    const SecByteBlock& key,
    const SecByteBlock& iv,
    const std::string& aad,
    const std::string& expectedTagHex)
{
    AEAD_DEC dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    dec.SpecifyDataLengths(aad.size(), GetFileSize(in), 0);

    const int TAG_SIZE = 16;
    SecByteBlock tag;
    DecodeHex(expectedTagHex, tag);

    // Dùng MAC_AT_END chuẩn theo behavior của GCM
    AuthenticatedDecryptionFilter df(
        dec,
        new FileSink(out.c_str()),
        AuthenticatedDecryptionFilter::MAC_AT_END |
        AuthenticatedDecryptionFilter::THROW_EXCEPTION,
        TAG_SIZE
    );

    // 1. Nạp AAD
    if (!aad.empty()) {
        df.ChannelPut(AAD_CHANNEL, reinterpret_cast<const byte*>(aad.data()), aad.size());
        df.ChannelMessageEnd(AAD_CHANNEL);
    }

    // 2. Bơm Ciphertext trước (bơm từng chunk nhỏ, tốn đúng 4KB RAM)
    std::ifstream infile(in, std::ios::binary);
    if (!infile) {
        throw std::runtime_error("Cannot open input ciphertext file.");
    }

    byte buffer[4096];
    while (infile.good()) {
        infile.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
        std::streamsize bytesRead = infile.gcount();
        if (bytesRead > 0) {
            // Nạp Ciphertext vào luồng mặc định
            df.ChannelPut(DEFAULT_CHANNEL, buffer, bytesRead);
        }
    }

    // 3. Bơm MAC vào SAU CÙNG (Nối đuôi Ciphertext)
    df.ChannelPut(DEFAULT_CHANNEL, tag.data(), tag.size());

    // 4. Chốt hạ luồng, Verify!
    df.ChannelMessageEnd(DEFAULT_CHANNEL);
}

    static void ProcessEncryption(const std::string& mode, const std::string& keyHex, const std::string& in, const std::string& out, bool allowEcb, std::string explicitIvHex = "", std::string aadStr = "") {
        SecByteBlock key, iv;
        DecodeHex(keyHex, key);

        if (mode == "ecb") {
            std::cout << "[!] WARNING: ECB mode is highly insecure and leaks data patterns.\n";
            size_t fsize = GetFileSize(in);
            if (fsize > 16384 && !allowEcb) {
                throw std::runtime_error("ECB mode is blocked for files larger than 16 KiB. Use --allow-ecb to override.");
            }
        }

        AutoSeededRandomPool prng;
        if (mode != "ecb") {
            if (explicitIvHex.empty()) {
                size_t ivLen = (mode == "gcm" || mode == "ccm") ? 12 : AES::BLOCKSIZE;
                iv.CleanNew(ivLen);
                prng.GenerateBlock(iv, iv.size());
                
                bool isStreamOrAEAD = (mode == "ctr" || mode == "gcm" || mode == "ccm");
                std::cout << "[*] Auto-generated secure random " << (isStreamOrAEAD ? "Nonce" : "IV") << ".\n";
            } else {
                DecodeHex(explicitIvHex, iv);
                if ((mode == "gcm" || mode == "ccm") && iv.size() != 12 && iv.size() != 16) {
                    throw std::invalid_argument("Cryptography Error: IV/Nonce length for GCM/CCM must be 12 or 16 bytes.");
                } else if (mode != "gcm" && mode != "ccm" && iv.size() != AES::BLOCKSIZE) {
                    throw std::invalid_argument("Cryptography Error: IV length must be exactly 16 bytes for this mode.");
                }
            }
        }

        std::string actualIvHex = "";
        if (iv.size() > 0) actualIvHex = EncodeHex(iv.data(), iv.size());

        NonceTracker::CheckAndRegister(mode, keyHex, actualIvHex);

        std::string tagHex = "";
        
        if (mode == "ecb") EncryptStandard<ECB_Mode<AES>::Encryption>(in, out, key, iv);
        else if (mode == "cbc") EncryptStandard<CBC_Mode<AES>::Encryption>(in, out, key, iv);
        else if (mode == "cfb") EncryptStandard<CFB_Mode<AES>::Encryption>(in, out, key, iv);
        else if (mode == "ofb") EncryptStandard<OFB_Mode<AES>::Encryption>(in, out, key, iv);
        else if (mode == "ctr") EncryptStandard<CTR_Mode<AES>::Encryption>(in, out, key, iv);
        else if (mode == "xts") EncryptStandard<XTS_Mode<AES>::Encryption>(in, out, key, iv);
        else if (mode == "gcm") EncryptAEAD<GCM<AES>::Encryption>(in, out, key, iv, aadStr, tagHex);
        else if (mode == "ccm") EncryptAEAD<CCM<AES>::Encryption>(in, out, key, iv, aadStr, tagHex);
        else throw std::invalid_argument("Unsupported mode: " + mode);

        SidecarMeta meta;
        meta.alg = "AES-" + std::to_string(key.size() * 8) + "-" + mode;
        if (iv.size() > 0) meta.iv_hex = actualIvHex;
        if (!aadStr.empty()) meta.aad_hex = EncodeHex(reinterpret_cast<const byte*>(aadStr.data()), aadStr.size());
        if (!tagHex.empty()) meta.tag_hex = tagHex;

        SaveSidecar(out + ".json", meta);
        std::cout << "[+] Encryption successful. Metadata saved to: " << out << ".json\n";
    }

    static void ProcessDecryption(const std::string& mode, const std::string& keyHex, const std::string& in, const std::string& out, std::string explicitIvHex = "", std::string explicitTagHex = "", std::string explicitAadStr = "") {
        SecByteBlock key, iv;
        DecodeHex(keyHex, key);

        SidecarMeta meta = LoadSidecar(in + ".json");
        
        std::string ivHexToUse = explicitIvHex.empty() ? meta.iv_hex : explicitIvHex;
        if (mode != "ecb" && ivHexToUse.empty()) throw std::runtime_error("Missing IV for decryption. Sidecar JSON not found or invalid.");
        if (!ivHexToUse.empty()) DecodeHex(ivHexToUse, iv);

        std::string tagHexToUse = explicitTagHex.empty() ? meta.tag_hex : explicitTagHex;
        
        std::string aadStr = explicitAadStr;
        if (aadStr.empty() && !meta.aad_hex.empty()) {
            SecByteBlock decodedAad;
            DecodeHex(meta.aad_hex, decodedAad);
            aadStr = std::string(reinterpret_cast<const char*>(decodedAad.data()), decodedAad.size());
        }

        if (mode == "ecb") DecryptStandard<ECB_Mode<AES>::Decryption>(in, out, key, iv);
        else if (mode == "cbc") DecryptStandard<CBC_Mode<AES>::Decryption>(in, out, key, iv);
        else if (mode == "cfb") DecryptStandard<CFB_Mode<AES>::Decryption>(in, out, key, iv);
        else if (mode == "ofb") DecryptStandard<OFB_Mode<AES>::Decryption>(in, out, key, iv);
        else if (mode == "ctr") DecryptStandard<CTR_Mode<AES>::Decryption>(in, out, key, iv);
        else if (mode == "xts") DecryptStandard<XTS_Mode<AES>::Decryption>(in, out, key, iv);
        else if (mode == "gcm") DecryptAEAD<GCM<AES>::Decryption>(in, out, key, iv, aadStr, tagHexToUse);
        else if (mode == "ccm") DecryptAEAD<CCM<AES>::Decryption>(in, out, key, iv, aadStr, tagHexToUse);
        else throw std::invalid_argument("Unsupported mode: " + mode);

        std::cout << "[+] Decryption successful. Output file: " << out << "\n";
    }
};

// =========================================================
// COMMAND LINE INTERFACE (CLI) & HELP MENU
// =========================================================
#ifndef AESTOOL_NO_MAIN
void PrintUsage(const char* prog_path) {
    std::string prog = fs::path(prog_path).filename().string();

    std::cout << "======================================================================\n";
    std::cout << "          AESTOOL - Symmetric Encryption Utility (Lab 1)              \n";
    std::cout << "======================================================================\n\n";
    
    std::cout << "USAGE:\n";
    std::cout << "  " << prog << " <command> [options]\n\n";
    
    std::cout << "COMMANDS:\n";
    std::cout << "  keygen    Generate a secure random AES key and save it as Hex.\n";
    std::cout << "  encrypt   Encrypt a file using the specified AES mode.\n";
    std::cout << "  decrypt   Decrypt a ciphertext file using the specified AES mode.\n\n";
    
    std::cout << "OPTIONS:\n";
    std::cout << "  --mode <mode>       AES mode (Required). Supported: ecb, cbc, ofb, cfb, ctr, xts, gcm, ccm.\n";
    std::cout << "  --key <file>        Path to the AES key file.\n";
    std::cout << "  --key-hex <hex>     Provide AES key directly as a Hex string (bypasses --key).\n";
    std::cout << "  --in <file>         Input file (Plaintext for encryption, Ciphertext for decryption).\n";
    std::cout << "  --out <file>        Output file to save the result.\n";
    std::cout << "  --iv <hex>          (Optional) Hex string for IV.\n";
    std::cout << "  --nonce <hex>       (Optional) Hex string for Nonce (Alias for --iv in CTR/GCM/CCM).\n";
    std::cout << "  --aead              (Optional) Enable authenticated encryption (Used with gcm/ccm).\n";
    std::cout << "  --aad-text <string> (Optional) Additional Authenticated Data (AAD).\n";
    std::cout << "  --allow-ecb         (Optional) Override security warning, force ECB mode for files > 16KiB.\n\n";

    std::cout << "NOTES & MISUSE PREVENTION:\n";
    std::cout << "  * Metadata (Alg, IV/Nonce, AAD, Tag) is automatically extracted and saved as a sidecar\n";
    std::cout << "    JSON file (e.g., ct.bin.json) during encryption for secure key management.\n";
    std::cout << "  * Nonce Reuse tracking is enforced for CTR/GCM/CCM. Operation will be rejected if \n";
    std::cout << "    the same Key+Nonce pair is detected in `.nonce_db`.\n";
    std::cout << "  * ECB mode is highly insecure (leaks data patterns) and is blocked by default\n";
    std::cout << "    for files larger than 16 KiB.\n\n";

    std::cout << "EXAMPLES:\n";
    std::cout << "  1. Encrypt with direct Hex Key and Nonce:\n";
    std::cout << "     " << prog << " encrypt --mode ctr --key-hex 8F4A9E6C... --nonce 9AC5E... --in msg.txt --out ct.bin\n\n";
    std::cout << "  2. Authenticated Encryption (AEAD) with GCM using Key file:\n";
    std::cout << "     " << prog << " encrypt --mode gcm --key mykey.hex --in msg.txt --out ct.bin --aad-text \"Header123\"\n";
    std::cout << "======================================================================\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) { 
        PrintUsage(argv[0]); 
        return 1; 
    }
    
    std::string cmd = argv[1];

    if (cmd == "-h" || cmd == "--help" || cmd == "help") {
        PrintUsage(argv[0]);
        return 0;
    }

    std::map<std::string, std::string> args;
    std::set<std::string> passed_flags; 
    bool allowEcb = false;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];

        if (passed_flags.find(arg) != passed_flags.end()) {
            std::cerr << "[!] Error: Duplicate argument '" << arg << "' is not allowed. Use -h for help.\n";
            return 1;
        }

        if (arg == "--allow-ecb") { 
            allowEcb = true; 
            passed_flags.insert(arg);
        }
        else if (arg == "--aead") { 
            passed_flags.insert(arg);
        }
        else if (arg.substr(0, 2) == "--") {
            if (i + 1 < argc && std::string(argv[i+1]).substr(0, 2) != "--") {
                args[arg] = argv[++i];
                passed_flags.insert(arg);
            } else {
                std::cerr << "[!] Error: Missing value for argument '" << arg << "'. Use -h for help.\n";
                return 1;
            }
        } else {
            std::cerr << "[!] Error: Invalid argument format '" << arg << "'. Use -h for help.\n";
            return 1;
        }
    }

    auto validate_args = [&](const std::set<std::string>& allowed_for_cmd) {
        for (const auto& flag : passed_flags) {
            if (allowed_for_cmd.find(flag) == allowed_for_cmd.end()) {
                throw std::invalid_argument("Argument '" + flag + "' is not valid for '" + cmd + "' command. Use -h for help.");
            }
        }
    };

    std::string current_out_file = "";

    try {
        if (cmd == "keygen") {
            validate_args({"--out"});
            
            if (!args.count("--out")) {
                throw std::invalid_argument("Missing required argument '--out'. Use -h for help.");
            }
            AES_App::GenerateKey(args["--out"], 32); 
        }
        else if (cmd == "encrypt" || cmd == "decrypt") {
            if (cmd == "encrypt") {
                validate_args({"--mode", "--key", "--key-hex", "--in", "--out", "--iv", "--nonce", "--aead", "--aad-text", "--allow-ecb"});
            } else {
                validate_args({"--mode", "--key", "--key-hex", "--in", "--out", "--iv", "--nonce", "--aead", "--aad-text", "--allow-ecb"});
            }

            if (!args.count("--mode") || !args.count("--in") || !args.count("--out")) {
                throw std::invalid_argument("Missing required arguments (--mode, --in, --out). Use -h for help.");
            }
            if (!args.count("--key") && !args.count("--key-hex")) {
                throw std::invalid_argument("Must provide --key or --key-hex. Use -h for help.");
            }

            current_out_file = args["--out"];
            std::string mode = args["--mode"];
            bool isStreamOrAEAD = (mode == "ctr" || mode == "gcm" || mode == "ccm");
            bool isAEAD = (mode == "gcm" || mode == "ccm");

            bool hasIv = args.count("--iv");
            bool hasNonce = args.count("--nonce");
            
            if (hasIv && hasNonce) {
                throw std::invalid_argument("Cannot use both --iv and --nonce. Use the appropriate one for your mode.");
            }

            if (isStreamOrAEAD && hasIv) {
                throw std::invalid_argument("Cryptography Error: Mode '" + mode + "' requires a unique Nonce. Please use --nonce instead of --iv.");
            }
            if (!isStreamOrAEAD && mode != "ecb" && hasNonce) {
                throw std::invalid_argument("Cryptography Error: Mode '" + mode + "' requires a random IV. Please use --iv instead of --nonce.");
            }

            std::string aadStr = args.count("--aad-text") ? args["--aad-text"] : "";
            if (!isAEAD && !aadStr.empty()) {
                throw std::invalid_argument("Logic Error: AAD (--aad-text) is only supported in AEAD modes (gcm, ccm).");
            }

            std::string keyHex;
            if (args.count("--key-hex")) {
                keyHex = args["--key-hex"];
            } else {
                std::ifstream keyfile(args["--key"]);
                if (!keyfile) throw std::runtime_error("Cannot open key file: " + args["--key"]);
                keyfile >> keyHex;
                if (keyHex.rfind("KEY=", 0) == 0) {
                    keyHex = keyHex.substr(4);
                }
            }

            std::string ivHex = hasIv ? args["--iv"] : (hasNonce ? args["--nonce"] : "");
            
            if (cmd == "encrypt") {
                AES_App::ProcessEncryption(mode, keyHex, args["--in"], args["--out"], allowEcb, ivHex, aadStr);
            } else {
                AES_App::ProcessDecryption(mode, keyHex, args["--in"], args["--out"], ivHex, "", aadStr);
            }
        }
        else {
            std::cerr << "[!] Error: Unknown command '" << cmd << "'. Use -h for help.\n";
            return 1;
        }
    } catch (const Exception& e) {  
        std::cerr << "[!] Crypto++ Exception: " << e.what() << "\n";
        if (!current_out_file.empty() && fs::exists(current_out_file)) {
            fs::remove(current_out_file);
            std::cerr << "[*] Security: Cleaned up invalid output file (" << current_out_file << ") to prevent leakage.\n";
        }
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        if (!current_out_file.empty() && fs::exists(current_out_file)) {
            fs::remove(current_out_file);
        }
        return 1;
    }
    return 0;
}
#endif