#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>

// Crypto++ Headers
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <cryptopp/misc.h> 
#include <cryptopp/queue.h>
#include <cryptopp/rsa.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/pssr.h>  
#include <cryptopp/sha.h>   

// ---------------------------------------------------------
// MACROS FOR DLL/SO EXPORT (CROSS-PLATFORM)
// ---------------------------------------------------------
#ifdef _WIN32
  #ifdef SIGTOOL_BUILD_DLL
    #define SIGTOOL_API extern "C" __declspec(dllexport)
  #elif defined(SIGTOOL_USE_DLL)
    #define SIGTOOL_API extern "C" __declspec(dllimport)
  #else
    #define SIGTOOL_API extern "C"
  #endif
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define SIGTOOL_API extern "C" __attribute__((visibility("default")))
  #else
    #define SIGTOOL_API extern "C"
  #endif
#endif

// =========================================================
// C API ERROR CODES
// =========================================================
#define SIGTOOL_SUCCESS 0
#define SIGTOOL_ERR_NULL_PTR -1
#define SIGTOOL_ERR_INVALID_PARAM -2
#define SIGTOOL_ERR_EXCEPTION -3

namespace util {

    // =========================================================
    // I/O ENUMS
    // =========================================================
    enum class OutputFormat { BINARY, HEX, BASE64 };
    enum class InputMode { TEXT, FILE };
    enum class KeyMaterialType { UNKNOWN, PUBLIC_KEY, PRIVATE_KEY };

    // =========================================================
    // SECURE WIPE MEMORY
    // =========================================================
    inline void SecureWipeString(std::string& str) {
        if (!str.empty()) {
            CryptoPP::SecureWipeArray(reinterpret_cast<CryptoPP::byte*>(&str[0]), str.size());
            str.clear();
        }
    }

    // =========================================================
    // STRING & FORMATTING UTILS
    // =========================================================
    std::string ToLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { 
            return static_cast<char>(std::tolower(c));
        });
        return s;
    }

    bool ParseEncodeFormat(const std::string& s, OutputFormat& fmt) {
        const std::string v = ToLower(s);
        if (v == "binary" || v == "bin" || v == "raw") { fmt = OutputFormat::BINARY; return true; }
        if (v == "hex") { fmt = OutputFormat::HEX; return true; }
        if (v == "base64" || v == "b64") { fmt = OutputFormat::BASE64; return true; }
        return false;
    }

    std::string GetBasePrefix(const std::string& path) {
        size_t dotPos = path.find_last_of('.');
        size_t sepPos = path.find_last_of("/\\"); 
        if (dotPos != std::string::npos && (sepPos == std::string::npos || dotPos > sepPos)) {
            return path.substr(0, dotPos); 
        }
        return path;
    }

    // =========================================================
    // ENCODE / DECODE (HEX & BASE64)
    // =========================================================
    std::string HexEncode(const std::string& data) {
        std::string encoded;
        CryptoPP::StringSource ss(data, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));
        return encoded;
    }

    std::string HexDecode(const std::string& hex) {
        std::string decoded;
        CryptoPP::StringSource ss(hex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }

    std::string Base64Encode(const std::string& data) {
        std::string encoded;
        CryptoPP::StringSource ss(data, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        return encoded;
    }

    std::string Base64Decode(const std::string& text) {
        std::string decoded;
        CryptoPP::StringSource ss(text, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }

    // =========================================================
    // FILE I/O
    // =========================================================
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

    // =========================================================
    // C-API ERROR WRITER
    // =========================================================
    void WriteError(char* buffer, uint32_t bufferSize, const std::string& msg) {
        if (!buffer || bufferSize == 0) return;
        const size_t maxCopy = static_cast<size_t>(bufferSize - 1);
        const size_t copyLen = (msg.size() < maxCopy) ? msg.size() : maxCopy;
        std::memcpy(buffer, msg.data(), copyLen);
        buffer[copyLen] = '\0';
    }

} 

namespace core {

    // =========================================================
    // PEM & DER FORMAT HELPER
    // =========================================================
    std::string DERToPEM(const std::string& derBytes, const std::string& header, const std::string& footer) {
        std::string base64;
        CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(derBytes.data()), derBytes.size(), true, 
                        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(base64), true, 64));
        return header + "\n" + base64 + footer + "\n";
    }

    std::string PEMToDER(const std::string& pemContent, const std::string& header) {
        size_t beginPos = pemContent.find(header);
        if (beginPos == std::string::npos) throw std::runtime_error("PEM header not found");
        
        size_t beginEnd = pemContent.find('\n', beginPos);
        size_t endPos = pemContent.find("-----END", beginEnd);
        if (endPos == std::string::npos) throw std::runtime_error("PEM footer not found");

        std::string base64 = pemContent.substr(beginEnd, endPos - beginEnd);
        base64.erase(std::remove_if(base64.begin(), base64.end(), ::isspace), base64.end());
        
        return util::Base64Decode(base64);
    }

    // =========================================================
    // CORE LOGIC: DIGITAL SIGNATURES
    // =========================================================
    class Sig_App {
    public:
        // 1. KEY GENERATION
        static void KeyGen(const std::string& algo, uint32_t bits, const std::string& pubFile, const std::string& privFile) {
            std::string pubBase = util::GetBasePrefix(pubFile);
            std::string privBase = util::GetBasePrefix(privFile);
            
            CryptoPP::AutoSeededRandomPool rng;
            std::string privDerBytes, pubDerBytes;
            std::string pubPemHeader, privPemHeader;

            try {
                if (algo == "rsa-pss-3072" || algo == "rsa-pss-4096") {
                    uint32_t rsaBits = (algo == "rsa-pss-3072") ? 3072 : 4096;
                    CryptoPP::InvertibleRSAFunction params;
                    params.Initialize(rng, rsaBits, CryptoPP::Integer(65537));

                    CryptoPP::RSA::PrivateKey privKey(params);
                    CryptoPP::RSA::PublicKey pubKey(params);

                    if (!privKey.Validate(rng, 3) || !pubKey.Validate(rng, 3))
                        throw std::runtime_error("RSA Key validation failed");

                    CryptoPP::ByteQueue privQ, pubQ;
                    privKey.Save(privQ);
                    pubKey.Save(pubQ);

                    privDerBytes.resize(privQ.CurrentSize());
                    privQ.Get(reinterpret_cast<CryptoPP::byte*>(&privDerBytes[0]), privDerBytes.size());
                    
                    pubDerBytes.resize(pubQ.CurrentSize());
                    pubQ.Get(reinterpret_cast<CryptoPP::byte*>(&pubDerBytes[0]), pubDerBytes.size());

                    privPemHeader = "-----BEGIN PRIVATE KEY-----";
                    pubPemHeader = "-----BEGIN PUBLIC KEY-----";
                    
                } 
                else if (algo == "ecdsa-p256" || algo == "ecdsa-p384") {
                    CryptoPP::OID curveOID = (algo == "ecdsa-p256") ? CryptoPP::ASN1::secp256r1() : CryptoPP::ASN1::secp384r1();
                    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params(curveOID);
                    
                    CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> privKey;
                    privKey.Initialize(rng, params);
                    CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> pubKey;
                    privKey.MakePublicKey(pubKey);

                    if (!privKey.Validate(rng, 3) || !pubKey.Validate(rng, 3))
                        throw std::runtime_error("ECDSA Key validation failed");

                    CryptoPP::ByteQueue privQ, pubQ;
                    privKey.Save(privQ);
                    pubKey.Save(pubQ);

                    privDerBytes.resize(privQ.CurrentSize());
                    privQ.Get(reinterpret_cast<CryptoPP::byte*>(&privDerBytes[0]), privDerBytes.size());

                    pubDerBytes.resize(pubQ.CurrentSize());
                    pubQ.Get(reinterpret_cast<CryptoPP::byte*>(&pubDerBytes[0]), pubDerBytes.size());

                    privPemHeader = "-----BEGIN PRIVATE KEY-----";
                    pubPemHeader = "-----BEGIN PUBLIC KEY-----";
                } 
                else {
                    throw std::invalid_argument("Unsupported algorithm. Use: rsa-pss-3072, rsa-pss-4096, ecdsa-p256, ecdsa-p384");
                }

                util::WriteFileBinary(privBase + ".der", privDerBytes);
                util::WriteFileBinary(pubBase + ".der", pubDerBytes);
                
                util::WriteFileBinary(privBase + ".pem", DERToPEM(privDerBytes, privPemHeader, std::string("-----END") + privPemHeader.substr(10)));
                util::WriteFileBinary(pubBase + ".pem", DERToPEM(pubDerBytes, pubPemHeader, std::string("-----END") + pubPemHeader.substr(10)));

                util::SecureWipeString(privDerBytes);
            } 
            catch (...) {
                util::SecureWipeString(privDerBytes);
                throw std::runtime_error("[!] Cryptographic operation failed: Key generation error."); 
            }
        }

        // 2. SIGNING
        static void SignData(util::InputMode inMode, const std::string& inValue, const std::string& keyPath, const std::string& outFile, util::OutputFormat outFormat, const std::string& algo) {
            std::string plaintext;
            std::string signature;
            CryptoPP::AutoSeededRandomPool rng;

            try {
                plaintext = (inMode == util::InputMode::FILE) ? util::ReadFileBinary(inValue) : inValue;
                
                std::string keyData = util::ReadFileBinary(keyPath);
                std::string derKey = (keyData.find("-----BEGIN") != std::string::npos) ? PEMToDER(keyData, "-----BEGIN") : keyData;
                util::SecureWipeString(keyData);
                
                CryptoPP::ByteQueue keyQueue;
                keyQueue.Put(reinterpret_cast<const CryptoPP::byte*>(derKey.data()), derKey.size());
                keyQueue.MessageEnd();

                if (algo.find("rsa-pss") != std::string::npos) {
                    CryptoPP::RSA::PrivateKey privKey;
                    privKey.Load(keyQueue);
                    
                    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(privKey);
                    
                    size_t sigLen = signer.MaxSignatureLength();
                    signature.resize(sigLen);
                    sigLen = signer.SignMessage(rng, reinterpret_cast<const CryptoPP::byte*>(plaintext.data()), plaintext.size(), reinterpret_cast<CryptoPP::byte*>(&signature[0]));
                    signature.resize(sigLen);
                } 
                else if (algo.find("ecdsa") != std::string::npos) {
                    CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> privKey;
                    privKey.Load(keyQueue);
                    
                    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(privKey);
                    
                    size_t sigLen = signer.MaxSignatureLength();
                    signature.resize(sigLen);
                    sigLen = signer.SignMessage(rng, reinterpret_cast<const CryptoPP::byte*>(plaintext.data()), plaintext.size(), reinterpret_cast<CryptoPP::byte*>(&signature[0]));
                    signature.resize(sigLen);
                }

                if (outFormat == util::OutputFormat::BASE64) signature = util::Base64Encode(signature);
                else if (outFormat == util::OutputFormat::HEX) signature = util::HexEncode(signature);

                if (outFile.empty()) std::cout << signature << "\n";
                else util::WriteFileBinary(outFile, signature);

                util::SecureWipeString(plaintext);
                util::SecureWipeString(derKey);
            } 
            catch (...) {
                util::SecureWipeString(plaintext);
                throw std::runtime_error("[!] Cryptographic operation failed: Integrity check or wrong key/format.");
            }
        }

        // 3. VERIFICATION
        static void VerifyData(util::InputMode inMode, const std::string& inValue, const std::string& sigPath, const std::string& keyPath, const std::string& algo) {
            std::string plaintext;
            
            try {
                plaintext = (inMode == util::InputMode::FILE) ? util::ReadFileBinary(inValue) : inValue;
                std::string sigData = util::ReadFileBinary(sigPath);
                std::string keyData = util::ReadFileBinary(keyPath);
                
                sigData.erase(sigData.find_last_not_of(" \n\r\t") + 1);

                if (sigData.find_first_not_of("0123456789abcdefABCDEFabcdef \n\r\t") == std::string::npos) {
                    sigData = util::HexDecode(sigData);
                } 
                else if (sigData.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \n\r\t") == std::string::npos) {
                    sigData = util::Base64Decode(sigData);
                }

                std::string derKey = (keyData.find("-----BEGIN") != std::string::npos) ? PEMToDER(keyData, "-----BEGIN") : keyData;
                
                CryptoPP::ByteQueue keyQueue;
                keyQueue.Put(reinterpret_cast<const CryptoPP::byte*>(derKey.data()), derKey.size());
                keyQueue.MessageEnd();

                bool result = false;

                if (algo.find("rsa-pss") != std::string::npos) {
                    CryptoPP::RSA::PublicKey pubKey;
                    pubKey.Load(keyQueue);
                    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Verifier verifier(pubKey);
                    
                    result = verifier.VerifyMessage(reinterpret_cast<const CryptoPP::byte*>(plaintext.data()), plaintext.size(),
                                                    reinterpret_cast<const CryptoPP::byte*>(sigData.data()), sigData.size());
                } 
                else if (algo.find("ecdsa") != std::string::npos) {
                    CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> pubKey;
                    pubKey.Load(keyQueue);
                    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(pubKey);
                    
                    result = verifier.VerifyMessage(reinterpret_cast<const CryptoPP::byte*>(plaintext.data()), plaintext.size(),
                                                    reinterpret_cast<const CryptoPP::byte*>(sigData.data()), sigData.size());
                }

                util::SecureWipeString(plaintext);

                if (!result) {
                    throw std::runtime_error("[!] Cryptographic operation failed: Integrity check or wrong key/format.");
                }

            } catch (...) {
                util::SecureWipeString(plaintext);
                throw std::runtime_error("[!] Cryptographic operation failed: Integrity check or wrong key/format.");
            }
        }
    };

}

// ============================================================================
// C-API EXPORTS AND MAIN CLI LOOP
// ============================================================================

SIGTOOL_API int sigtool_keygen(const char* algo, uint32_t bits, const char* pub_file, const char* priv_file, char* err_msg, uint32_t err_size) {
    try {
        if (!algo || !pub_file || !priv_file) throw std::invalid_argument("Pointers cannot be null");
        core::Sig_App::KeyGen(algo, bits, pub_file, priv_file);
        util::WriteError(err_msg, err_size, "");
        return SIGTOOL_SUCCESS;
    } catch (const std::exception& e) {
        util::WriteError(err_msg, err_size, e.what());
        return SIGTOOL_ERR_EXCEPTION;
    }
}

#ifndef SIGTOOL_NO_MAIN

struct CryptoConfig {
    std::string command;
    std::string algo;
    std::string keyPath;
    std::string sigPath;
    util::InputMode inMode;
    std::string inValue;
    std::string outFile;
    util::OutputFormat outFormat;
};

void PrintUsage(const char* prog) {
    std::cerr
        << "Usage:\n"
        << "  " << prog << " keygen --algo <ecdsa-p256|rsa-pss-3072> --pub <pub_prefix> --priv <priv_prefix>\n"
        << "  " << prog << " sign   --algo <algo> (--in <file> | --text <str>) --priv <priv.pem> [--out <file>] [--encode hex|base64|raw]\n"
        << "  " << prog << " verify --algo <algo> (--in <file> | --text <str>) --sig <sig_file> --pub <pub.pem>\n\n"
        << "Run '" << prog << " --help' for more info.\n";
}

void PrintHelp(const char* prog) {
    std::cerr << "=========================================================\n";
    std::cerr << "     SIGTOOL - Classical Digital Signatures Utility      \n";
    std::cerr << "=========================================================\n\n";
    PrintUsage(prog);
    std::cerr
        << "\nOptions:\n"
        << "  --algo <algo>      Algorithm: ecdsa-p256, ecdsa-p384, rsa-pss-3072, rsa-pss-4096.\n"
        << "  --pub <path>       Public Key file.\n"
        << "  --priv <path>      Private Key file.\n"
        << "  --in <path>        Input file to sign/verify.\n"
        << "  --text <string>    Input plain text to sign/verify.\n"
        << "  --sig <path>       Signature file (Required for verify).\n"
        << "  --out <path>       Output file. Prints to screen if omitted.\n"
        << "  --encode <fmt>     Encoding: raw | hex | base64.\n"
        << "=========================================================\n";
}

class CliParser {
public:
    static CryptoConfig Parse(int argc, char* argv[], const std::string& command) {
        CryptoConfig cfg;
        cfg.command = command;
        
        std::map<std::string, std::string> args;
        
        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg.rfind("--", 0) == 0) {
                if (i + 1 >= argc || argv[i+1][0] == '-') throw std::invalid_argument("Missing value for parameter: " + arg);
                if (args.count(arg)) throw std::invalid_argument("Duplicate parameter: " + arg);
                args[arg] = argv[++i];
            } else {
                throw std::invalid_argument("Unknown positional argument: " + arg);
            }
        }

        if (!args.count("--algo")) throw std::invalid_argument("Missing required parameter: --algo");
        cfg.algo = util::ToLower(args["--algo"]);

        if (command == "keygen") {
            if (!args.count("--pub") || !args.count("--priv")) throw std::invalid_argument("Keygen requires both --pub and --priv");
            cfg.keyPath = args["--pub"] + "|" + args["--priv"]; 
            return cfg;
        }

        bool hasIn = args.count("--in");
        bool hasText = args.count("--text");
        if (hasIn == hasText) throw std::invalid_argument("Must specify exactly one input mode: --in OR --text");
        
        cfg.inMode = hasText ? util::InputMode::TEXT : util::InputMode::FILE;
        cfg.inValue = hasText ? args["--text"] : args["--in"];

        if (command == "sign") {
            if (!args.count("--priv")) throw std::invalid_argument("Signing requires --priv <private_key>");
            cfg.keyPath = args["--priv"];
            cfg.outFile = args.count("--out") ? args["--out"] : "";
            
            cfg.outFormat = cfg.outFile.empty() ? util::OutputFormat::HEX : util::OutputFormat::BINARY;
            if (args.count("--encode") && !util::ParseEncodeFormat(args["--encode"], cfg.outFormat)) {
                throw std::invalid_argument("Invalid --encode format");
            }
        } 
        else if (command == "verify") {
            if (!args.count("--pub")) throw std::invalid_argument("Verification requires --pub <public_key>");
            if (!args.count("--sig")) throw std::invalid_argument("Verification requires --sig <signature_file>");
            cfg.keyPath = args["--pub"];
            cfg.sigPath = args["--sig"];
        }

        return cfg;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) { PrintUsage(argv[0]); return 1; }
    
    std::string command = argv[1];
    if (command == "--help" || command == "-h") { PrintHelp(argv[0]); return 0; }

    try {
        CryptoConfig cfg = CliParser::Parse(argc, argv, command);

        if (cfg.command == "keygen") {
            uint32_t bits = (cfg.algo.find("4096") != std::string::npos) ? 4096 : 3072;
            std::string pubBase = cfg.keyPath.substr(0, cfg.keyPath.find('|'));
            std::string privBase = cfg.keyPath.substr(cfg.keyPath.find('|') + 1);
            core::Sig_App::KeyGen(cfg.algo, bits, pubBase, privBase);
            std::cout << "[+] Keypair generated successfully for " << cfg.algo << "\n";
        } 
        else if (cfg.command == "sign") {
            core::Sig_App::SignData(cfg.inMode, cfg.inValue, cfg.keyPath, cfg.outFile, cfg.outFormat, cfg.algo);
            if (!cfg.outFile.empty()) std::cout << "[+] Message signed successfully. Output: " << cfg.outFile << "\n";
        } 
        else if (cfg.command == "verify") {
            core::Sig_App::VerifyData(cfg.inMode, cfg.inValue, cfg.sigPath, cfg.keyPath, cfg.algo);
            std::cout << "[+] VERIFICATION SUCCESS: The signature is authentic and the message is unaltered.\n";
        } 
        else {
            std::cerr << "Unknown command: " << command << "\n";
            PrintUsage(argv[0]);
            return 1;
        }

    } 
    catch (const std::invalid_argument& e) {
        std::cerr << "[!] Input Syntax Error: " << e.what() << "\n";
        PrintUsage(argv[0]);
        return 1;
    } 
    catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}
#endif