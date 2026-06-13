#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <fstream>
#include <random>
#include <iomanip>
#include <openssl/evp.h>

using namespace std;

// Wrapper hỗ trợ Hashing bằng OpenSSL
class BenchHasher {
private:
    const EVP_MD* md;
    bool is_xof;
public:
    BenchHasher(const string& algo) {
        OpenSSL_add_all_digests();
        is_xof = (algo == "shake128" || algo == "shake256");
        md = EVP_get_digestbyname(algo.c_str());
        if (!md) throw runtime_error("Unsupported algorithm: " + algo);
    }

    // 1. Chế độ In-Memory (Hash trực tiếp từ RAM)
    void hash_memory(const unsigned char* data, size_t len, int outlen = 32) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, data, len);

        if (is_xof) {
            vector<unsigned char> safe_buf(outlen, 0);
            EVP_DigestFinalXOF(ctx, safe_buf.data(), outlen);
        } else {
            vector<unsigned char> digest(EVP_MAX_MD_SIZE);
            unsigned int digest_len = 0;
            EVP_DigestFinal_ex(ctx, digest.data(), &digest_len);
        }
        EVP_MD_CTX_free(ctx);
    }

    // 2. Chế độ Streaming I/O (Đọc từng Chunk 8KB từ ổ cứng)
    void hash_stream(const string& filepath, int outlen = 32) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, md, nullptr);

        ifstream file(filepath, ios::binary);
        vector<char> buffer(8192); // Chunk 8KB
        while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
            EVP_DigestUpdate(ctx, buffer.data(), file.gcount());
        }

        if (is_xof) {
            vector<unsigned char> safe_buf(outlen, 0);
            EVP_DigestFinalXOF(ctx, safe_buf.data(), outlen);
        } else {
            vector<unsigned char> digest(EVP_MAX_MD_SIZE);
            unsigned int digest_len = 0;
            EVP_DigestFinal_ex(ctx, digest.data(), &digest_len);
        }
        EVP_MD_CTX_free(ctx);
    }
};

// Hàm sinh file giả định với Seed cố định
void generate_dummy_file(const string& filename, size_t sizeBytes) {
    cout << "    -> Generating " << sizeBytes / (1024*1024) << "MB synthetic file (PRNG Fixed Seed)... " << flush;
    ofstream out(filename, ios::binary);
    mt19937 gen(12345); // Seed cố định
    uniform_int_distribution<int> dist(0, 255);
    
    vector<char> buf(1024 * 1024); // Sinh từng 1MB để tránh tràn RAM
    size_t written = 0;
    while (written < sizeBytes) {
        size_t to_write = min(buf.size(), sizeBytes - written);
        for(size_t i=0; i<to_write; ++i) buf[i] = static_cast<char>(dist(gen));
        out.write(buf.data(), to_write);
        written += to_write;
    }
    cout << "Done.\n";
}

int main() {
    vector<string> algos = {"sha256", "sha512", "sha3-256", "sha3-512"};
    vector<size_t> sizes = {1024 * 1024, 100 * 1024 * 1024, 1024 * 1024 * 1024}; // 1MB, 100MB, 1GB
    int num_runs = 30;

    cout << "==================================================\n";
    cout << "   LAB 4 - PERFORMANCE BENCHMARK (STANDALONE)\n";
    cout << "==================================================\n";

    ofstream csv("lab4_benchmark_results.csv");
    csv << "Algorithm,Mode,Size_MB,Mean_ms,Median_ms,StdDev_ms,CI95_ms,Throughput_MBs\n";

    string dummy_file = "dummy_test.bin";

    for (size_t size : sizes) {
        cout << "\n[*] =================== PAYLOAD: " << size / (1024 * 1024) << " MiB ===================\n";
        generate_dummy_file(dummy_file, size);
        
        // Load data lên RAM 1 lần để dùng chung cho In-Memory tests
        cout << "    -> Loading file to RAM for In-Memory tests... " << flush;
        vector<unsigned char> ram_data(size);
        ifstream in(dummy_file, ios::binary);
        in.read(reinterpret_cast<char*>(ram_data.data()), size);
        in.close();
        cout << "Done.\n";

        for (const auto& algo : algos) {
            try {
                BenchHasher hasher(algo);
                for (string mode : {"In-Memory", "Streaming"}) {
                    cout << "\n    [*] Algo: " << algo << " | Mode: " << mode << "\n";
                    
                    // Warm-up 1s
                    cout << "        - Warming up... " << flush;
                    auto start_warmup = chrono::high_resolution_clock::now();
                    while (chrono::duration_cast<chrono::seconds>(chrono::high_resolution_clock::now() - start_warmup).count() < 1) {
                        if (mode == "In-Memory") hasher.hash_memory(ram_data.data(), ram_data.size());
                        else hasher.hash_stream(dummy_file);
                    }
                    cout << "Done.\n";

                    // Chạy 30 vòng (Riêng 1GB Streaming chạy 10 vòng để tránh cháy ổ SSD)
                    int current_runs = (mode == "Streaming" && size >= 1024*1024*1024) ? 10 : num_runs;
                    cout << "        - Benchmarking (N=" << current_runs << ")...\n";

                    vector<double> latencies;
                    for (int i = 0; i < current_runs; ++i) {
                        auto start = chrono::high_resolution_clock::now();
                        
                        if (mode == "In-Memory") hasher.hash_memory(ram_data.data(), ram_data.size());
                        else hasher.hash_stream(dummy_file);
                        
                        auto end = chrono::high_resolution_clock::now();
                        latencies.push_back(chrono::duration<double, milli>(end - start).count());
                    }

                    // Tính toán Thống kê
                    double sum = accumulate(latencies.begin(), latencies.end(), 0.0);
                    double mean = sum / current_runs;
                    
                    vector<double> sorted = latencies;
                    sort(sorted.begin(), sorted.end());
                    double median = (current_runs % 2 == 0) ? (sorted[current_runs/2 - 1] + sorted[current_runs/2]) / 2.0 : sorted[current_runs/2];
                    
                    double sq_sum = inner_product(latencies.begin(), latencies.end(), latencies.begin(), 0.0);
                    double stdev = sqrt(sq_sum / current_runs - mean * mean);
                    double ci95 = 1.96 * (stdev / sqrt(current_runs));
                    
                    double throughput = (size / (1024.0 * 1024.0)) / (mean / 1000.0); 

                    cout << "        -> Throughput : " << fixed << setprecision(2) << throughput << " MB/s\n";
                    cout << "        -> Latency    : " << mean << " ms (±" << ci95 << ")\n";

                    // Xuất CSV
                    csv << algo << "," << mode << "," << size/(1024*1024) << "," 
                        << mean << "," << median << "," << stdev << "," << ci95 << "," << throughput << "\n";
                }
            } catch (const exception& e) {
                cout << "[-] Error running " << algo << ": " << e.what() << "\n";
            }
        }
        // Xóa file dummy đi cho nhẹ máy
        remove(dummy_file.c_str());
    }
    
    csv.close();
    cout << "\n[+] Hoan tat! Du lieu da duoc luu ra lab4_benchmark_results.csv\n";
    return 0;
}