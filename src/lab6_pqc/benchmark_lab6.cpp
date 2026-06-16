#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <fstream>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;
using namespace std::chrono;

// ==========================================
// THỐNG KÊ (STATISTICS)
// ==========================================
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

void HandleOpenSSLErrors(const string& context) {
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    throw runtime_error(context + ": " + string(err_buf));
}

// ==========================================
// 1. BENCHMARK ML-DSA (SIGNATURE)
// ==========================================
void bench_mldsa(const string& algo_name, ofstream& csv) {
    cout << "\n[*] Benchmarking " << algo_name << " (Signature)...\n";
    
    vector<double> kg_times;
    EVP_PKEY* final_pkey = nullptr;
    
    // 1.1 KEYGEN
    for(int i = 0; i < 30; ++i) {
        auto start = high_resolution_clock::now();
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, algo_name.c_str(), nullptr);
        if (!ctx) HandleOpenSSLErrors("Khong the tim thay " + algo_name);
        
        if (EVP_PKEY_keygen_init(ctx) <= 0) HandleOpenSSLErrors("Keygen init failed");
        
        // FIX LỖI: Luôn dùng con trỏ mới cho mỗi lần sinh khóa
        EVP_PKEY* temp_pkey = nullptr; 
        if (EVP_PKEY_keygen(ctx, &temp_pkey) <= 0) HandleOpenSSLErrors("Keygen failed");
        
        auto end = high_resolution_clock::now();
        kg_times.push_back(duration<double, milli>(end - start).count());
        
        // Chỉ giữ lại key cuối cùng, các key còn lại free ngay lập tức
        if (i == 29) { 
            final_pkey = temp_pkey; 
        } else { 
            EVP_PKEY_free(temp_pkey); 
        }
        EVP_PKEY_CTX_free(ctx);
    }
    
    Stats kg_stat = calc_stats(kg_times);
    cout << "    -> Keygen: " << kg_stat.mean << " ms\n";
    csv << algo_name << ",Keygen,N/A," << kg_stat.mean << "," << kg_stat.median << "," << kg_stat.stddev << "," << kg_stat.ci95 << ",N/A\n";

    // 1.2 SIGN & VERIFY CHO CÁC MỐC FILE
    vector<pair<string, size_t>> sizes = { {"1 KiB", 1024}, {"16 KiB", 16384}, {"1 MiB", 1048576}, {"8 MiB", 8388608} };
    
    for (const auto& s : sizes) {
        vector<unsigned char> msg(s.second, 0xAB);
        size_t siglen;
        
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, final_pkey);
        EVP_DigestSign(mdctx, nullptr, &siglen, msg.data(), msg.size());
        vector<unsigned char> sig(siglen);

        int ops = (s.second >= 1048576) ? 10 : 50; 

        // Đo Sign
        vector<double> sign_times;
        for(int i = 0; i < 30; ++i) {
            auto start = high_resolution_clock::now();
            for(int j=0; j<ops; ++j) {
                EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, final_pkey);
                EVP_DigestSign(mdctx, sig.data(), &siglen, msg.data(), msg.size());
            }
            auto end = high_resolution_clock::now();
            sign_times.push_back(duration<double, milli>(end - start).count() / ops);
        }
        Stats ss_stat = calc_stats(sign_times);
        double sign_ops_sec = 1000.0 / ss_stat.mean;

        // Đo Verify
        vector<double> ver_times;
        for(int i = 0; i < 30; ++i) {
            auto start = high_resolution_clock::now();
            for(int j=0; j<ops; ++j) {
                EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, final_pkey);
                EVP_DigestVerify(mdctx, sig.data(), siglen, msg.data(), msg.size());
            }
            auto end = high_resolution_clock::now();
            ver_times.push_back(duration<double, milli>(end - start).count() / ops);
        }
        Stats sv_stat = calc_stats(ver_times);
        double ver_ops_sec = 1000.0 / sv_stat.mean;

        cout << "    -> " << s.first << " | Sign: " << ss_stat.mean << " ms | Verify: " << sv_stat.mean << " ms\n";
        csv << algo_name << ",Sign," << s.first << "," << ss_stat.mean << "," << ss_stat.median << "," << ss_stat.stddev << "," << ss_stat.ci95 << "," << sign_ops_sec << "\n";
        csv << algo_name << ",Verify," << s.first << "," << sv_stat.mean << "," << sv_stat.median << "," << sv_stat.stddev << "," << sv_stat.ci95 << "," << ver_ops_sec << "\n";
        
        EVP_MD_CTX_free(mdctx);
    }
    EVP_PKEY_free(final_pkey);
}

// ==========================================
// 2. BENCHMARK ML-KEM (ENCAPSULATION)
// ==========================================
void bench_mlkem(const string& algo_name, ofstream& csv) {
    cout << "\n[*] Benchmarking " << algo_name << " (KEM)...\n";
    
    vector<double> kg_times;
    EVP_PKEY* final_pkey = nullptr;
    
    // 2.1 KEYGEN
    for(int i = 0; i < 30; ++i) {
        auto start = high_resolution_clock::now();
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, algo_name.c_str(), nullptr);
        if (!ctx) HandleOpenSSLErrors("Khong the tim thay " + algo_name);
        
        if (EVP_PKEY_keygen_init(ctx) <= 0) HandleOpenSSLErrors("Keygen init failed");
        
        EVP_PKEY* temp_pkey = nullptr; 
        if (EVP_PKEY_keygen(ctx, &temp_pkey) <= 0) HandleOpenSSLErrors("Keygen failed");
        
        auto end = high_resolution_clock::now();
        kg_times.push_back(duration<double, milli>(end - start).count());
        
        if (i == 29) { 
            final_pkey = temp_pkey; 
        } else { 
            EVP_PKEY_free(temp_pkey); 
        }
        EVP_PKEY_CTX_free(ctx);
    }
    Stats kg_stat = calc_stats(kg_times);
    cout << "    -> Keygen: " << kg_stat.mean << " ms\n";
    csv << algo_name << ",Keygen,N/A," << kg_stat.mean << "," << kg_stat.median << "," << kg_stat.stddev << "," << kg_stat.ci95 << ",N/A\n";

    EVP_PKEY_CTX* enctx = EVP_PKEY_CTX_new(final_pkey, nullptr);
    if (EVP_PKEY_encapsulate_init(enctx, nullptr) <= 0) HandleOpenSSLErrors("Encapsulate init failed");
    
    size_t ctlen, sslen;
    EVP_PKEY_encapsulate(enctx, nullptr, &ctlen, nullptr, &sslen);
    vector<unsigned char> ct(ctlen);
    vector<unsigned char> ss(sslen);
    vector<unsigned char> decaps_ss(sslen);

    int ops = 100;

    // 2.2 ENCAPSULATION
    vector<double> enc_times;
    for(int i = 0; i < 30; ++i) {
        auto start = high_resolution_clock::now();
        for(int j=0; j<ops; ++j) {
            EVP_PKEY_encapsulate_init(enctx, nullptr);
            EVP_PKEY_encapsulate(enctx, ct.data(), &ctlen, ss.data(), &sslen);
        }
        auto end = high_resolution_clock::now();
        enc_times.push_back(duration<double, milli>(end - start).count() / ops);
    }
    Stats enc_stat = calc_stats(enc_times);
    
    // 2.3 DECAPSULATION
    EVP_PKEY_CTX* dectx = EVP_PKEY_CTX_new(final_pkey, nullptr);
    vector<double> dec_times;
    for(int i = 0; i < 30; ++i) {
        auto start = high_resolution_clock::now();
        for(int j=0; j<ops; ++j) {
            EVP_PKEY_decapsulate_init(dectx, nullptr);
            EVP_PKEY_decapsulate(dectx, decaps_ss.data(), &sslen, ct.data(), ctlen);
        }
        auto end = high_resolution_clock::now();
        dec_times.push_back(duration<double, milli>(end - start).count() / ops);
    }
    Stats dec_stat = calc_stats(dec_times);

    cout << "    -> Encaps: " << enc_stat.mean << " ms | Decaps: " << dec_stat.mean << " ms\n";
    csv << algo_name << ",Encaps,N/A," << enc_stat.mean << "," << enc_stat.median << "," << enc_stat.stddev << "," << enc_stat.ci95 << "," << (1000.0/enc_stat.mean) << "\n";
    csv << algo_name << ",Decaps,N/A," << dec_stat.mean << "," << dec_stat.median << "," << dec_stat.stddev << "," << dec_stat.ci95 << "," << (1000.0/dec_stat.mean) << "\n";

    EVP_PKEY_CTX_free(enctx);
    EVP_PKEY_CTX_free(dectx);
    EVP_PKEY_free(final_pkey);
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    cout << "==================================================\n";
    cout << "   LAB 6 - POST-QUANTUM CRYPTOGRAPHY BENCHMARK\n";
    cout << "==================================================\n";

    ofstream csv("lab6_benchmark_results.csv");
    csv << "Algorithm,Operation,Size_Label,Mean_ms,Median_ms,StdDev_ms,CI95_ms,Throughput_Ops_Sec\n";

    try {
        bench_mldsa("ML-DSA-44", csv);
        bench_mldsa("ML-DSA-65", csv); 
        bench_mlkem("ML-KEM-512", csv);
        bench_mlkem("ML-KEM-768", csv);
    } catch (const exception& e) {
        cerr << "\n[-] LOI: " << e.what() << "\n";
    }

    csv.close();
    cout << "\n[+] Hoan tat! Du lieu da duoc luu ra lab6_benchmark_results.csv\n";
    
    return 0;
}