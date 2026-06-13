#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <iomanip>

using namespace CryptoPP;
using namespace std::chrono;

// ---------------------------------------------------------
// 1. HÀM IN THỐNG KÊ (GIỮ NGUYÊN TỪ BẢN CŨ)
// ---------------------------------------------------------
void print_stats(const std::string& name, std::vector<double>& latencies) {
    double sum = std::accumulate(latencies.begin(), latencies.end(), 0.0);
    double mean = sum / latencies.size();
    
    std::vector<double> sorted = latencies;
    std::sort(sorted.begin(), sorted.end());
    double median = (sorted.size() % 2 == 0) ? 
        (sorted[sorted.size()/2 - 1] + sorted[sorted.size()/2]) / 2.0 : 
        sorted[sorted.size()/2];
        
    double sq_sum = std::inner_product(latencies.begin(), latencies.end(), latencies.begin(), 0.0);
    double stdev = std::sqrt(sq_sum / latencies.size() - mean * mean);
    double ci = 1.96 * (stdev / std::sqrt(latencies.size()));
    
    std::cout << std::left << std::setw(15) << name 
              << ": Mean = " << std::fixed << std::setprecision(3) << mean 
              << " ms, Median = " << median 
              << " ms, StdDev = " << stdev 
              << " ms, 95% CI = [" << (mean - ci) << ", " << (mean + ci) << "]\n";
}

// ---------------------------------------------------------
// 2. HÀM WARM-UP CPU ĐỂ TRÁNH NHIỄU CACHE
// ---------------------------------------------------------
void warmup_cpu() {
    auto start = high_resolution_clock::now();
    std::string dummy(1024, 'W');
    std::string out;
    SHA256 hash;
    // Chạy các phép băm liên tục trong 1.5 giây để làm nóng CPU
    while(duration<double>(high_resolution_clock::now() - start).count() < 1.5) {
        StringSource(dummy, true, new HashFilter(hash, new StringSink(out)));
        out.clear();
    }
}

// ---------------------------------------------------------
// 3. BENCHMARK MÃ HÓA RSA THUẦN
// ---------------------------------------------------------
void benchmark_rsa(int bits) {
    AutoSeededRandomPool rng;
    int num_runs = 30;
    int ops_per_block = 1000; // Yêu cầu chạy ~1000 ops cho mỗi lần đo

    std::cout << "[*] Benchmarking RSA-" << bits << " (N=" << num_runs << ", Ops/Block=" << ops_per_block << ")\n";
    warmup_cpu(); // Làm nóng hệ thống trước khi đo
    
    // Đo Keygen (Keygen rất nặng, ta đo 1 lần mỗi run thay vì 1000 để tránh chờ hàng tiếng)
    std::vector<double> keygen_times;
    for (int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();
        InvertibleRSAFunction params;
        params.Initialize(rng, bits, Integer(65537));
        auto end = high_resolution_clock::now();
        keygen_times.push_back(duration<double, std::milli>(end - start).count());
    }
    
    // Setup key để đo Encrypt/Decrypt
    InvertibleRSAFunction params;
    params.Initialize(rng, bits, Integer(65537));
    RSA::PrivateKey priv(params);
    RSA::PublicKey pub(params);
    RSAES_OAEP_SHA256_Encryptor enc(pub);
    RSAES_OAEP_SHA256_Decryptor dec(priv);
    
    std::string msg = "This is a payload test for RSA-OAEP benchmarking.";
    std::string ct;
    ct.resize(enc.CiphertextLength(msg.size()));

    // Đo Encrypt (1000 vòng/block)
    std::vector<double> enc_times;
    for(int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();
        for(int j = 0; j < ops_per_block; j++) { 
            enc.Encrypt(rng, (const byte*)msg.data(), msg.size(), (byte*)ct.data());
        }
        auto end = high_resolution_clock::now();
        // Tính trung bình thời gian cho 1 operation trong block
        enc_times.push_back(duration<double, std::milli>(end - start).count() / ops_per_block);
    }

    // Đo Decrypt (1000 vòng/block)
    std::vector<double> dec_times;
    std::string recovered;
    recovered.resize(dec.MaxPlaintextLength(ct.size()));
    for(int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();
        for(int j = 0; j < ops_per_block; j++) {
            dec.Decrypt(rng, (const byte*)ct.data(), ct.size(), (byte*)recovered.data());
        }
        auto end = high_resolution_clock::now();
        dec_times.push_back(duration<double, std::milli>(end - start).count() / ops_per_block);
    }

    print_stats("  - Keygen", keygen_times);
    print_stats("  - Encrypt", enc_times);
    print_stats("  - Decrypt", dec_times);
    std::cout << "--------------------------------------------------\n";
}

// ---------------------------------------------------------
// 4. BENCHMARK HYBRID ENCRYPTION (TÁCH RIÊNG AES VÀ RSA)
// ---------------------------------------------------------
void benchmark_hybrid(size_t payload_size, const std::string& size_label, int ops_per_block) {
    AutoSeededRandomPool rng;
    int num_runs = 30;

    std::cout << "[*] Benchmarking Hybrid Encryption - " << size_label 
              << " (N=" << num_runs << ", Ops/Block=" << ops_per_block << ")\n";
    
    warmup_cpu();

    // Setup khóa RSA 3072 chuẩn để Wrap Key
    InvertibleRSAFunction params;
    params.Initialize(rng, 3072, Integer(65537));
    RSA::PublicKey pubKey(params);
    RSAES_OAEP_SHA256_Encryptor rsaEncryptor(pubKey);

    std::string plaintext(payload_size, 'A'); // Tạo payload rác

    std::vector<double> hybrid_times;
    std::vector<double> throughput_mbs;

    for (int i = 0; i < num_runs; i++) {
        double block_hybrid_ms = 0.0;
        double block_aes_sec = 0.0;

        for (int j = 0; j < ops_per_block; j++) {
            // Bước 1: Random AES Key & IV (Thao tác này nằm ngoài thời gian đo AES Core)
            SecByteBlock aesKey(AES::MAX_KEYLENGTH); // 32 bytes (256-bit)
            SecByteBlock iv(12);
            rng.GenerateBlock(aesKey, aesKey.size());
            rng.GenerateBlock(iv, iv.size());

            // BẮT ĐẦU ĐO THỜI GIAN TOÀN TRÌNH HYBRID
            auto start_hybrid = high_resolution_clock::now();

            // Bước 2: Đo ĐỘC LẬP tốc độ mã hóa AES-GCM
            auto start_aes = high_resolution_clock::now();
            std::string aesCiphertext;
            GCM<AES>::Encryption gcm;
            gcm.SetKeyWithIV(aesKey, aesKey.size(), iv, iv.size());
            StringSource(plaintext, true, new AuthenticatedEncryptionFilter(gcm, new StringSink(aesCiphertext)));
            auto end_aes = high_resolution_clock::now();

            // Bước 3: Wrap khóa AES bằng RSA
            std::string wrappedKey;
            StringSource(aesKey.data(), aesKey.size(), true, new PK_EncryptorFilter(rng, rsaEncryptor, new StringSink(wrappedKey)));

            // KẾT THÚC ĐO THỜI GIAN TOÀN TRÌNH HYBRID
            auto end_hybrid = high_resolution_clock::now();
            
            // Tích lũy thời gian trong block
            block_hybrid_ms += duration<double, std::milli>(end_hybrid - start_hybrid).count();
            block_aes_sec += duration<double>(end_aes - start_aes).count();
        }

        // Trung bình Latency Hybrid cho 1 thao tác
        hybrid_times.push_back(block_hybrid_ms / ops_per_block);
        
        // Tính Throughput AES-GCM (MB/s) = (Dung lượng x Số vòng) / Tổng thời gian AES
        double total_mb_processed = (static_cast<double>(payload_size) * ops_per_block) / (1024.0 * 1024.0);
        throughput_mbs.push_back(total_mb_processed / block_aes_sec);
    }

    print_stats("  - Latency", hybrid_times);
    
    // In trung bình Throughput
    double sum_thpt = std::accumulate(throughput_mbs.begin(), throughput_mbs.end(), 0.0);
    std::cout << "  - Throughput : " << std::fixed << std::setprecision(2) << (sum_thpt / num_runs) << " MB/s\n";
    std::cout << "--------------------------------------------------\n";
}

int main() {
    std::cout << "==================================================\n";
    std::cout << "   LAB 3 - RSA-OAEP & HYBRID BENCHMARK\n";
    std::cout << "==================================================\n";
    
    benchmark_rsa(3072);
    benchmark_rsa(4096);
    
    // Mức ops_per_block được hạ dần khi dung lượng tăng để tránh treo máy / tràn RAM
    benchmark_hybrid(1024, "1 KB", 1000);                // Chạy 1000 vòng cho 1 KB
    benchmark_hybrid(1024 * 1024, "1 MB", 100);          // Chạy 100 vòng cho 1 MB
    benchmark_hybrid(100 * 1024 * 1024, "100 MB", 1);    // Chạy 1 vòng cho 100 MB

    return 0;
}