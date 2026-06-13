#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/xts.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>

using namespace std;
using namespace CryptoPP;
using namespace std::chrono;

const int RUNS = 30;
const int OPS_PER_RUN = 1000;

// Hàm in mảng chuẩn Python
void PrintPythonArray(const string& varName, const vector<double>& times) {
    cout << varName << " = [";
    for (size_t i = 0; i < times.size(); ++i) {
        cout << fixed << setprecision(3) << times[i] << (i == times.size() - 1 ? "" : ", ");
    }
    cout << "]" << endl;
}

// CType: 0 = Bình thường & XTS, 1 = ECB (Không IV), 3 = AEAD (GCM, CCM)
template<class ENC_MODE, class DEC_MODE, int CType = 0>
void RunBench(const string& modeName, const string& sizeLabel, size_t sizeBytes, int keySize = 16) {
    AutoSeededRandomPool prng;
    SecByteBlock key(keySize);
    SecByteBlock iv(16);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    string pt(sizeBytes, 'A');
    string ct, tempDump;

    // FIX CHUẨN 1000%: XTS xài chung SetKeyWithIV với nhóm 0!
    auto InitCipher = [&](auto& cipherObj) {
        if constexpr (CType == 1) { 
            // ECB: Tuyệt đối không dùng IV
            cipherObj.SetKey(key, key.size()); 
        } else if constexpr (CType == 3) {
            // AEAD (GCM, CCM): Cần IV và SpecifyDataLengths
            cipherObj.SetKeyWithIV(key, key.size(), iv, cipherObj.IVSize()); 
            cipherObj.SpecifyDataLengths(0, sizeBytes, 0); 
        } else {
            // CTR, CBC, OFB, CFB, XTS: Dùng IV bình thường
            cipherObj.SetKeyWithIV(key, key.size(), iv, cipherObj.IVSize()); 
        }
    };

    // ==========================================
    // 0. CHUẨN BỊ CIPHERTEXT
    // ==========================================
    ENC_MODE encSetup;
    InitCipher(encSetup);

    if constexpr (CType == 3) {
        StringSource(pt, true, new AuthenticatedEncryptionFilter(encSetup, new StringSink(ct)));
    } else {
        StringSource(pt, true, new StreamTransformationFilter(encSetup, new StringSink(ct)));
    }

    // ==========================================
    // 1. WARM-UP CPU (1 Giây)
    // ==========================================
    auto wStart = high_resolution_clock::now();
    while (duration_cast<seconds>(high_resolution_clock::now() - wStart).count() < 1) {
        ENC_MODE encW;
        InitCipher(encW);
        if constexpr (CType == 3) StringSource(pt, true, new AuthenticatedEncryptionFilter(encW, new StringSink(tempDump)));
        else StringSource(pt, true, new StreamTransformationFilter(encW, new StringSink(tempDump)));
        tempDump.clear();
    }

    // ==========================================
    // 2. BENCHMARK ENCRYPTION
    // ==========================================
    vector<double> encTimes;
    for (int i = 0; i < RUNS; ++i) {
        auto start = high_resolution_clock::now();
        for (int j = 0; j < OPS_PER_RUN; ++j) {
            ENC_MODE enc;
            InitCipher(enc);
            if constexpr (CType == 3) StringSource(pt, true, new AuthenticatedEncryptionFilter(enc, new StringSink(tempDump)));
            else StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(tempDump)));
            tempDump.clear();
        }
        auto end = high_resolution_clock::now();
        encTimes.push_back(duration_cast<duration<double, milli>>(end - start).count());
    }

    // ==========================================
    // 3. BENCHMARK DECRYPTION
    // ==========================================
    vector<double> decTimes;
    for (int i = 0; i < RUNS; ++i) {
        auto start = high_resolution_clock::now();
        for (int j = 0; j < OPS_PER_RUN; ++j) {
            DEC_MODE dec;
            InitCipher(dec);
            if constexpr (CType == 3) {
                StringSource(ct, true, new AuthenticatedDecryptionFilter(dec, new StringSink(tempDump), AuthenticatedDecryptionFilter::DEFAULT_FLAGS));
            } else {
                StringSource(ct, true, new StreamTransformationFilter(dec, new StringSink(tempDump)));
            }
            tempDump.clear();
        }
        auto end = high_resolution_clock::now();
        decTimes.push_back(duration_cast<duration<double, milli>>(end - start).count());
    }

    PrintPythonArray(modeName + "_enc_" + sizeLabel, encTimes);
    PrintPythonArray(modeName + "_dec_" + sizeLabel, decTimes);
}

int main() {
    vector<pair<string, size_t>> payloads = {
        {"1KB", 1024}, {"4KB", 4096}, {"16KB", 16384},
        {"256KB", 262144}, {"1MB", 1048576}, {"8MB", 8388608}
    };

    cout << "# ========== FULL AES BENCHMARK (ENC & DEC) FOR PYTHON ==========" << endl;
    cout << "repetitions = list(range(1, 31))" << endl << endl;

    for (const auto& p : payloads) {
        cout << "# --- Payload: " << p.first << " ---" << endl;
        
        // CType = 0 (Bình thường + XTS)
        RunBench<CTR_Mode<AES>::Encryption, CTR_Mode<AES>::Decryption, 0>("ctr", p.first, p.second);
        RunBench<CBC_Mode<AES>::Encryption, CBC_Mode<AES>::Decryption, 0>("cbc", p.first, p.second);
        RunBench<OFB_Mode<AES>::Encryption, OFB_Mode<AES>::Decryption, 0>("ofb", p.first, p.second);
        RunBench<CFB_Mode<AES>::Encryption, CFB_Mode<AES>::Decryption, 0>("cfb", p.first, p.second);
        RunBench<XTS_Mode<AES>::Encryption, XTS_Mode<AES>::Decryption, 0>("xts", p.first, p.second, 32);
        
        // CType = 1 (Chỉ có ECB)
        RunBench<ECB_Mode<AES>::Encryption, ECB_Mode<AES>::Decryption, 1>("ecb", p.first, p.second);
        
        // CType = 3 (Nhóm AEAD - GCM, CCM)
        RunBench<GCM<AES>::Encryption, GCM<AES>::Decryption, 3>("gcm", p.first, p.second);
        RunBench<CCM<AES, 16>::Encryption, CCM<AES, 16>::Decryption, 3>("ccm", p.first, p.second);
        
        cout << endl;
    }
    return 0;
}