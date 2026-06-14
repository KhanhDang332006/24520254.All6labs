#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

// ---------------------------------------------------------
// MACROS FOR DLL/SO EXPORT (CROSS-PLATFORM)
// ---------------------------------------------------------
#ifdef _WIN32
  #ifdef PKITOOL_BUILD_DLL
    #define PKI_API extern "C" __declspec(dllexport)
  #elif defined(PKITOOL_USE_DLL)
    #define PKI_API extern "C" __declspec(dllimport)
  #else
    #define PKI_API extern "C"
  #endif
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define PKI_API extern "C" __attribute__((visibility("default")))
  #else
    #define PKI_API extern "C"
  #endif
#endif

// =========================================================
// C API ERROR CODES
// =========================================================
#define PKI_SUCCESS 0
#define PKI_ERR_NULL_PTR -1
#define PKI_ERR_INVALID_FORMAT -2
#define PKI_ERR_EXCEPTION -3

namespace util {
    std::string ReadFileBinary(const std::string& filename) {
        std::ifstream in(filename, std::ios::binary);
        if (!in) throw std::runtime_error("Fail Closed: Failed to open file for reading: " + filename);
        return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }

    void WriteError(char* buffer, uint32_t bufferSize, const std::string& msg) {
        if (!buffer || bufferSize == 0) return;
        const size_t maxCopy = static_cast<size_t>(bufferSize - 1);
        const size_t copyLen = (msg.size() < maxCopy) ? msg.size() : maxCopy;
        std::memcpy(buffer, msg.data(), copyLen);
        buffer[copyLen] = '\0';
    }
}

// =========================================================
// LỚP XỬ LÝ LÕI X.509 (Giữ nguyên logic cũ nhưng xài BIO memory)
// =========================================================
class PKI_App {
private:
    static std::string Asn1TimeToString(const ASN1_TIME* tm) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) return "Unknown";
        ASN1_TIME_print(bio, tm);
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string res(data, len);
        BIO_free(bio);
        return res;
    }

    static void PrintSans(X509* cert) {
        GENERAL_NAMES* sans = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
        if (!sans) {
            std::cout << "[+] SANs: None\n";
            return;
        }
        std::cout << "[+] Subject Alternative Names (SANs):\n";
        int num = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < num; ++i) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(sans, i);
            if (name->type == GEN_DNS) {
                char* dns_str = nullptr;
                ASN1_STRING_to_UTF8((unsigned char**)&dns_str, name->d.dNSName);
                if (dns_str) {
                    std::cout << "  - DNS: " << dns_str << "\n";
                    OPENSSL_free(dns_str);
                }
            }
        }
        GENERAL_NAMES_free(sans);
    }

    static void PrintKeyUsage(X509* cert) {
        uint32_t usage = X509_get_key_usage(cert);
        if (usage == UINT32_MAX) {
            std::cout << "[+] Key Usage: Not Specified\n";
            return;
        }
        std::cout << "[+] Key Usage: ";
        if (usage & KU_DIGITAL_SIGNATURE) std::cout << "Digital Signature, ";
        if (usage & KU_NON_REPUDIATION) std::cout << "Non-Repudiation, ";
        if (usage & KU_KEY_ENCIPHERMENT) std::cout << "Key Encipherment, ";
        if (usage & KU_DATA_ENCIPHERMENT) std::cout << "Data Encipherment, ";
        if (usage & KU_KEY_AGREEMENT) std::cout << "Key Agreement, ";
        if (usage & KU_KEY_CERT_SIGN) std::cout << "Certificate Signing, ";
        if (usage & KU_CRL_SIGN) std::cout << "CRL Signing, ";
        std::cout << "\n";
    }

public:
    static void Analyze(const std::string& certFile, const std::string& issuerKeyFile) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // Đọc qua BIO Memory (chuẩn hóa luồng I/O chung toàn project)
        std::string certData = util::ReadFileBinary(certFile);
        BIO* certBio = BIO_new_mem_buf(certData.data(), certData.size());
        X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
        BIO_free(certBio);

        if (!cert) throw std::runtime_error("Fail Closed: File chứng chỉ không đúng định dạng X.509 chuẩn.");

        std::cout << "\n==================================================\n";
        std::cout << "          X.509 CERTIFICATE ANALYSIS\n";
        std::cout << "==================================================\n";

        char* subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        std::cout << "[+] Subject : " << (subj ? subj : "Unknown") << "\n";
        std::cout << "[+] Issuer  : " << (issuer ? issuer : "Unknown") << "\n";
        if (subj) OPENSSL_free(subj);
        if (issuer) OPENSSL_free(issuer);

        std::cout << "[+] Validity Period:\n";
        std::cout << "  - Not Before: " << Asn1TimeToString(X509_get0_notBefore(cert)) << "\n";
        std::cout << "  - Not After : " << Asn1TimeToString(X509_get0_notAfter(cert)) << "\n";

        EVP_PKEY* pubkey = X509_get_pubkey(cert);
        if (pubkey) {
            int type = EVP_PKEY_id(pubkey);
            int bits = EVP_PKEY_bits(pubkey);
            std::cout << "[+] Subject Public Key Info:\n";
            std::cout << "  - Algorithm: " << OBJ_nid2ln(type) << "\n";
            std::cout << "  - Key Size : " << bits << " bits\n";
            EVP_PKEY_free(pubkey);
        } else {
            std::cout << "[-] Subject Public Key Info: Failed to extract\n";
        }

        int sig_nid = X509_get_signature_nid(cert);
        std::cout << "[+] Signature Algorithm: " << OBJ_nid2ln(sig_nid) << "\n";

        PrintKeyUsage(cert);
        PrintSans(cert);

        std::cout << "--------------------------------------------------\n";
        if (!issuerKeyFile.empty()) {
            std::string keyData = util::ReadFileBinary(issuerKeyFile);
            BIO* keyBio = BIO_new_mem_buf(keyData.data(), keyData.size());
            EVP_PKEY* issuer_pubkey = PEM_read_bio_PUBKEY(keyBio, nullptr, nullptr, nullptr);
            BIO_free(keyBio);

            if (!issuer_pubkey) {
                X509_free(cert);
                throw std::runtime_error("Fail Closed: Lỗi đọc public key của Issuer.");
            }

            if (X509_verify(cert, issuer_pubkey) == 1) {
                std::cout << "[PASS] Signature Verification: Valid (Verified with external Issuer Key)\n";
            } else {
                std::cout << "[FAIL] Signature Verification: Invalid (Verification failed)\n";
            }
            EVP_PKEY_free(issuer_pubkey);
        } else {
            EVP_PKEY* self_pubkey = X509_get_pubkey(cert);
            if (self_pubkey) {
                if (X509_verify(cert, self_pubkey) == 1) {
                    std::cout << "[PASS] Signature Verification: Valid (Self-Signed Certificate)\n";
                } else {
                    std::cout << "[FAIL] Signature Verification: Fail (Requires external CA public key via --issuer-key)\n";
                }
                EVP_PKEY_free(self_pubkey);
            }
        }
        std::cout << "==================================================\n\n";

        X509_free(cert);
    }
};

// =========================================================
// EXPORT C-API (ĐỂ TÍCH HỢP GUI SAU NÀY NẾU CẦN)
// =========================================================
PKI_API int pkitool_analyze_cert(const char* cert_file, const char* issuer_key_file, char* err_msg, uint32_t err_size) {
    try {
        if (!cert_file) throw std::invalid_argument("Certificate file path cannot be null");
        std::string issuer = issuer_key_file ? issuer_key_file : "";
        PKI_App::Analyze(cert_file, issuer);
        util::WriteError(err_msg, err_size, "");
        return PKI_SUCCESS;
    } catch (const std::exception& e) {
        util::WriteError(err_msg, err_size, e.what());
        return PKI_ERR_EXCEPTION;
    }
}

// ============================================================================
// COMMAND LINE INTERFACE (UNIFIED ARCHITECTURE)
// ============================================================================
#ifndef PKITOOL_NO_MAIN

struct CryptoConfig {
    std::string certFile;
    std::string issuerKeyFile;
    bool isVerbose = false;
};

void PrintUsage(const char* prog) {
    std::cerr
        << "Usage:\n"
        << "  " << prog << " --in <cert.pem> [--issuer-key <public_key.pem>]\n"
        << "Run '" << prog << " --help' for full options.\n";
}

void PrintHelp(const char* prog) {
    std::cerr << "=========================================================\n";
    std::cerr << "         PKITOOL - X.509 Certificate Analyzer            \n";
    std::cerr << "=========================================================\n\n";
    PrintUsage(prog);
    std::cerr
        << "\nOPTIONS:\n"
        << "  --in <path>           Path to the X.509 certificate file (PEM).\n"
        << "  --issuer-key <path>   Optional. Issuer's public key to verify the signature.\n"
        << "  --verbose             Enable detailed execution logs.\n"
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
            if (arg == "--verbose") { flags.insert(arg); continue; }
            
            if (arg.rfind("--", 0) == 0) {
                if (i + 1 >= argc || argv[i+1][0] == '-') throw std::invalid_argument("Fail Closed: Thiếu giá trị cho tham số " + arg);
                if (args.count(arg)) throw std::invalid_argument("Fail Closed: Tham số " + arg + " bị lặp lại.");
                args[arg] = argv[++i];
            } else throw std::invalid_argument("Fail Closed: Tham số không hợp lệ " + arg);
        }

        cfg.isVerbose = flags.count("--verbose");

        if (!args.count("--in")) throw std::invalid_argument("Fail Closed: Bắt buộc phải có tham số --in.");
        cfg.certFile = args["--in"];

        if (args.count("--issuer-key")) {
            cfg.issuerKeyFile = args["--issuer-key"];
        }

        return cfg;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) { PrintUsage(argv[0]); return 1; }

    std::string first_arg = argv[1];
    if (first_arg == "--help" || first_arg == "-h") { PrintHelp(argv[0]); return 0; }

    try {
        CryptoConfig cfg = CliParser::Parse(argc, argv);
        
        if (cfg.isVerbose) {
            std::cout << "[INFO] Target Certificate : " << cfg.certFile << "\n";
            if (!cfg.issuerKeyFile.empty())
                std::cout << "[INFO] Issuer Public Key  : " << cfg.issuerKeyFile << "\n";
        }

        PKI_App::Analyze(cfg.certFile, cfg.issuerKeyFile);

    } 
    catch (const std::exception& e) {
        std::cerr << "[!] CRITICAL ERROR: " << e.what() << "\n";
        return 1; 
    }
    return 0;
}
#endif