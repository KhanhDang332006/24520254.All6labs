#define LIB_EXPORTS // Bỏ qua hàm main() trong aesToolPureCPP.cpp để tránh xung đột
#include "aesToolPureCPP.cpp"

#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <random>

using namespace std;

struct BenchResult {
    string sizeLabel;
    size_t sizeBytes;
    double mean_ms;
    double median_ms;
    double stddev_ms;
    double ci95_ms;
    double throughput_mbs;
};

BenchResult runBenchmark(const string& sizeLabel, size_t payloadBytes) {
    // Sinh Key và IV ngẫu nhiên theo chuẩn (16 bytes)
    vector<uint8_t> key(16), iv(16);
    mt19937 gen(12345); // Seed cố định cho Repeatability
    uniform_int_distribution<int> dist(0, 255);
    for(int i = 0; i < 16; i++) {
        key[i] = static_cast<uint8_t>(dist(gen));
        iv[i] = static_cast<uint8_t>(dist(gen));
    }

    cout << " -> Allocating " << sizeLabel << " RAM... " << flush;
    vector<uint8_t> plainText(payloadBytes);
    vector<uint8_t> cipherText(payloadBytes);
    // Sinh payload giả định
    for (size_t i = 0; i < payloadBytes; ++i) {
        plainText[i] = static_cast<uint8_t>(dist(gen));
    }
    cout << "Done.\n";

    // Tính OPS_PER_RUN: Do 100MB và 1GB quá lớn, ta chỉ chạy 1 thao tác mỗi vòng lặp 
    // để tránh bị treo máy. Với 1MB thì chạy 50 thao tác/vòng.
    const int OPS_PER_RUN = (payloadBytes >= 104857600) ? 1 : 50; 
    const int N = 30; // Lặp 30 lần độc lập

    // 1. Warm-up (1 giây) làm nóng Cache CPU
    cout << " -> Warming up... " << flush;
    auto warmup_start = chrono::high_resolution_clock::now();
    while (chrono::duration_cast<chrono::seconds>(chrono::high_resolution_clock::now() - warmup_start).count() < 1) {
        aes_ctr_encrypt(plainText.data(), payloadBytes, key.data(), key.size(), iv.data(), iv.size(), cipherText.data());
    }
    cout << "Done.\n";

    // 2. Tiến hành đo đạc N=30 lần
    cout << " -> Benchmarking (N=30, Ops=" << OPS_PER_RUN << ")... " << flush;
    vector<double> latencies;
    for (int i = 0; i < N; ++i) {
        auto start = chrono::high_resolution_clock::now();
        for (int op = 0; op < OPS_PER_RUN; ++op) {
            aes_ctr_encrypt(plainText.data(), payloadBytes, key.data(), key.size(), iv.data(), iv.size(), cipherText.data());
        }
        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double, milli> elapsed = end - start;
        latencies.push_back(elapsed.count() / OPS_PER_RUN);
    }
    cout << "Done.\n";

    // 3. Tính toán thống kê
    double sum = accumulate(latencies.begin(), latencies.end(), 0.0);
    double mean = sum / N;

    sort(latencies.begin(), latencies.end());
    double median = (latencies[N / 2 - 1] + latencies[N / 2]) / 2.0;

    double sq_sum = inner_product(latencies.begin(), latencies.end(), latencies.begin(), 0.0);
    double stddev = sqrt(sq_sum / N - mean * mean);
    double ci95 = 1.96 * (stddev / sqrt(N)); // 95% Confidence Interval

    // Tính Throughput (MB/s)
    double sizeMB = payloadBytes / (1024.0 * 1024.0);
    double throughput = sizeMB / (mean / 1000.0);

    return {sizeLabel, payloadBytes, mean, median, stddev, ci95, throughput};
}

int main() {
    // Mốc payload chuẩn của Lab 2 (1 MiB, 100 MiB, 1 GiB)
    vector<pair<string, size_t>> sizes = {
        {"1 MiB", 1048576},
        {"100 MiB", 104857600},
        {"1 GiB", 1073741824}
    };
    
    ofstream csv("lab2_benchmark_results.csv");
    csv << "Mode,Size_Label,Mean_ms,Median_ms,StdDev_ms,CI95_ms,Throughput_MBs\n";

    cout << "[*] Bat dau Benchmark Lab 2 (Pure C++ AES-128 CTR). Vui long cho...\n";

    for (const auto& s : sizes) {
        cout << "\nTesting payload: " << s.first << "\n";
        auto res = runBenchmark(s.first, s.second);

        csv << "Pure_AES_CTR," << res.sizeLabel << "," << fixed << setprecision(4) 
            << res.mean_ms << "," << res.median_ms << "," << res.stddev_ms << "," 
            << res.ci95_ms << "," << res.throughput_mbs << "\n";
    }

    csv.close();
    cout << "\n[+] Hoan tat! Du lieu duoc luu tai lab2_benchmark_results.csv\n";
    return 0;
}