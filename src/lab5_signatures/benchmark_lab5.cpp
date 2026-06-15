#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <fstream>
#include <iomanip>

#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>

using namespace std;
using namespace std::chrono;
using namespace CryptoPP;

// Cấu trúc lưu trữ thống kê
struct Stats {
    double mean, median, stddev, ci95;
};

Stats calc_stats(vector<double>& times) {
    int n = times.size();
    if (n == 0) return {0, 0, 0, 0};
    
    double sum = accumulate(times.begin(), times.end(), 0.0);
    double mean = sum / n;
    
    vector<double> sorted = times;
    sort(sorted.begin(), sorted.end());
    double median = (n % 2 == 0) ? (sorted[n/2 - 1] + sorted[n/2]) / 2.0 : sorted[n/2];
    
    double sq_sum = inner_product(times.begin(), times.end(), times.begin(), 0.0);
    double stdev = sqrt(sq_sum / n - mean * mean);
    double ci95 = 1.96 * (stdev / sqrt(n));
    
    return {mean, median, stdev, ci95};
}

// 1. HÀM BENCHMARK KEYGEN
template <typename KeyType, typename CurveType>
void bench_ecdsa_keygen(const CurveType& curve, const string& algo_name, ofstream& csv) {
    AutoSeededRandomPool prng;
    cout << "[*] Benchmarking Keygen: " << algo_name << " ... " << flush;
    
    // Warm-up
    auto start_w = high_resolution_clock::now();
    while(duration_cast<seconds>(high_resolution_clock::now() - start_w).count() < 1) {
        KeyType priv;
        priv.Initialize(prng, curve);
    }
    
    vector<double> times;
    for(int i = 0; i < 30; ++i) {
        auto start = high_resolution_clock::now();
        KeyType priv;
        priv.Initialize(prng, curve);
        auto end = high_resolution_clock::now();
        times.push_back(duration<double, milli>(end - start).count());
    }
    
    Stats s = calc_stats(times);
    cout << s.mean << " ms\n";
    csv << algo_name << ",Keygen,N/A," << s.mean << "," << s.median << "," << s.stddev << "," << s.ci95 << ",N/A\n";
}

void bench_rsa_keygen(int bits, const string& algo_name, ofstream& csv) {
    AutoSeededRandomPool prng;
    cout << "[*] Benchmarking Keygen: " << algo_name << " ... " << flush;
    
    // Warm-up 1 lần vì RSA keygen rất lâu
    InvertibleRSAFunction p_warm;
    p_warm.GenerateRandomWithKeySize(prng, bits);
    
    vector<double> times;
    for(int i = 0; i < 30; ++i) {
        auto start = high_resolution_clock::now();
        InvertibleRSAFunction priv;
        priv.GenerateRandomWithKeySize(prng, bits);
        auto end = high_resolution_clock::now();
        times.push_back(duration<double, milli>(end - start).count());
    }
    
    Stats s = calc_stats(times);
    cout << s.mean << " ms\n";
    csv << algo_name << ",Keygen,N/A," << s.mean << "," << s.median << "," << s.stddev << "," << s.ci95 << ",N/A\n";
}

// 2. HÀM BENCHMARK SIGN & VERIFY
template <typename SignerType, typename VerifierType>
void bench_sign_verify(const string& algo_name, const SignerType& signer, const VerifierType& verifier, size_t size_bytes, const string& size_label, ofstream& csv) {
    AutoSeededRandomPool prng;
    // Fix lỗi ambiguous byte bằng cách gọi rõ CryptoPP::byte
    vector<CryptoPP::byte> msg(size_bytes, 0xAB); // Synthetic payload
    
    string signature;
    size_t max_sig_len = signer.MaxSignatureLength();
    signature.resize(max_sig_len);
    
    // Lấy thử một chữ ký hợp lệ để verify
    size_t actual_sig_len = signer.SignMessage(prng, msg.data(), msg.size(), (CryptoPP::byte*)signature.data());
    signature.resize(actual_sig_len);
    
    int ops = (size_bytes >= 1048576) ? 10 : 50; // Giảm vòng lặp với file lớn tránh treo máy
    
    // --- Đo lường Ký (Sign) ---
    auto start_w = high_resolution_clock::now();
    while(duration_cast<seconds>(high_resolution_clock::now() - start_w).count() < 1) {
        signer.SignMessage(prng, msg.data(), msg.size(), (CryptoPP::byte*)signature.data());
    }
    
    vector<double> sign_times;
    for(int i = 0; i < 30; ++i) {
        auto start = high_resolution_clock::now();
        for(int j = 0; j < ops; ++j) {
            signer.SignMessage(prng, msg.data(), msg.size(), (CryptoPP::byte*)signature.data());
        }
        auto end = high_resolution_clock::now();
        sign_times.push_back(duration<double, milli>(end - start).count() / ops);
    }
    Stats ss_stat = calc_stats(sign_times);
    double sign_ops_sec = 1000.0 / ss_stat.mean;
    
    // --- Đo lường Xác minh (Verify) ---
    start_w = high_resolution_clock::now();
    while(duration_cast<seconds>(high_resolution_clock::now() - start_w).count() < 1) {
        verifier.VerifyMessage(msg.data(), msg.size(), (const CryptoPP::byte*)signature.data(), signature.size());
    }
    
    vector<double> ver_times;
    for(int i = 0; i < 30; ++i) {
        auto start = high_resolution_clock::now();
        for(int j = 0; j < ops; ++j) {
            verifier.VerifyMessage(msg.data(), msg.size(), (const CryptoPP::byte*)signature.data(), signature.size());
        }
        auto end = high_resolution_clock::now();
        ver_times.push_back(duration<double, milli>(end - start).count() / ops);
    }
    Stats sv_stat = calc_stats(ver_times);
    double ver_ops_sec = 1000.0 / sv_stat.mean;
    
    cout << "    -> " << size_label << " | Sign: " << fixed << setprecision(3) << ss_stat.mean 
         << " ms | Verify: " << sv_stat.mean << " ms\n";
         
    csv << algo_name << ",Sign," << size_label << "," << ss_stat.mean << "," << ss_stat.median << "," << ss_stat.stddev << "," << ss_stat.ci95 << "," << sign_ops_sec << "\n";
    csv << algo_name << ",Verify," << size_label << "," << sv_stat.mean << "," << sv_stat.median << "," << sv_stat.stddev << "," << sv_stat.ci95 << "," << ver_ops_sec << "\n";
}

int main() {
    cout << "==================================================\n";
    cout << "   LAB 5 - CLASSICAL DIGITAL SIGNATURES BENCHMARK\n";
    cout << "==================================================\n";

    ofstream csv("lab5_benchmark_results.csv");
    csv << "Algorithm,Operation,Size_Label,Mean_ms,Median_ms,StdDev_ms,CI95_ms,Throughput_Ops_Sec\n";

    AutoSeededRandomPool prng;

    // 1. BENCKMARK KEYGEN
    bench_ecdsa_keygen<ECDSA<ECP, SHA256>::PrivateKey>(ASN1::secp256r1(), "ECDSA-P256", csv);
    bench_ecdsa_keygen<ECDSA<ECP, SHA384>::PrivateKey>(ASN1::secp384r1(), "ECDSA-P384", csv);
    bench_rsa_keygen(3072, "RSA-PSS-3072", csv);
    cout << "--------------------------------------------------\n";

    // Khởi tạo các KeyPair để test Sign/Verify
    ECDSA<ECP, SHA256>::PrivateKey ecdsa256Priv;
    ecdsa256Priv.Initialize(prng, ASN1::secp256r1());
    ECDSA<ECP, SHA256>::PublicKey ecdsa256Pub;
    ecdsa256Priv.MakePublicKey(ecdsa256Pub);
    ECDSA<ECP, SHA256>::Signer ecdsa256Signer(ecdsa256Priv);
    ECDSA<ECP, SHA256>::Verifier ecdsa256Verifier(ecdsa256Pub);

    ECDSA<ECP, SHA384>::PrivateKey ecdsa384Priv;
    ecdsa384Priv.Initialize(prng, ASN1::secp384r1());
    ECDSA<ECP, SHA384>::PublicKey ecdsa384Pub;
    ecdsa384Priv.MakePublicKey(ecdsa384Pub);
    ECDSA<ECP, SHA384>::Signer ecdsa384Signer(ecdsa384Priv);
    ECDSA<ECP, SHA384>::Verifier ecdsa384Verifier(ecdsa384Pub);

    InvertibleRSAFunction rsaParams;
    rsaParams.GenerateRandomWithKeySize(prng, 3072);
    RSA::PrivateKey rsaPriv(rsaParams);
    RSA::PublicKey rsaPub(rsaParams);
    RSASS<PSS, SHA256>::Signer rsaSigner(rsaPriv);
    RSASS<PSS, SHA256>::Verifier rsaVerifier(rsaPub);

    vector<pair<string, size_t>> sizes = {
        {"1 KiB", 1024},
        {"16 KiB", 16384},
        {"1 MiB", 1048576},
        {"8 MiB", 8388608}
    };

    // 2. BENCHMARK SIGN & VERIFY
    for (const auto& algo : {"ECDSA-P256", "ECDSA-P384", "RSA-PSS-3072"}) {
        cout << "[*] Benchmarking " << algo << " (Sign/Verify)...\n";
        for (const auto& s : sizes) {
            if (string(algo) == "ECDSA-P256") 
                bench_sign_verify(algo, ecdsa256Signer, ecdsa256Verifier, s.second, s.first, csv);
            else if (string(algo) == "ECDSA-P384") 
                bench_sign_verify(algo, ecdsa384Signer, ecdsa384Verifier, s.second, s.first, csv);
            else 
                bench_sign_verify(algo, rsaSigner, rsaVerifier, s.second, s.first, csv);
        }
        cout << "--------------------------------------------------\n";
    }

    csv.close();
    cout << "[+] Hoan tat! Du lieu da duoc luu ra lab5_benchmark_results.csv\n";
    return 0;
}