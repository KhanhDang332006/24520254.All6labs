# Cryptography & Applications - Laboratory Series (Labs 1-6)

## Project Overview
This repository contains the source code, unit tests, and build scripts for Labs 1-6 of the Cryptography & Applications course. The project implements and analyzes modern cryptographic primitives, applies secure engineering practices, and validates correctness using official NIST test vectors.

**Author:** Khánh Đăng
**Major:** Information Security
**Institution:** University of Information Technology (UIT)

## Dependencies
To build and run the tools, the following dependencies are required:
* **C++ Compiler:** Modern C++17 support (GCC 10+ or MSVC)
* **Build System:** CMake (3.15 or higher)
* **Crypto++:** Cloned from the official GitHub repository
* **OpenSSL:** Version 3.6.2 

## Installation Instructions

### 1. Windows - MinGW64 (MSYS2)
**Prerequisites Setup:**
1. Install [MSYS2](https://www.msys2.org/).
2. Open MSYS2 MinGW 64-bit terminal and install the required toolchains:
   ```bash
   pacman -Syu
   pacman -S git mingw-w64-x86_64-gcc base-devel mingw-w64-cross-binutils
   pacman -S mingw64/mingw-w64-x86_64-perl mingw64/mingw-w64-x86_64-nasm cmake
   ```
3. Add `C:\\msys64\\mingw64\\bin` and `C:\\msys64\\usr\\bin` to your Windows Environment Variables `Path`.

**Compile Crypto++:**
```bash
git clone [https://github.com/weidai11/cryptopp](https://github.com/weidai11/cryptopp)
cd cryptopp
make CXX="/mingw64/bin/g++" -j $(nproc)
mkdir -p "D:/Labs_Crypto/cryptopp/include/cryptopp" "D:/Labs_Crypto/cryptopp/lib/gcc"
cp *.h -p "D:/Labs_Crypto/cryptopp/include/cryptopp"
cp *.a *.so -p "D:/Labs_Crypto/cryptopp/lib/gcc"
```

**Compile OpenSSL (3.6.2):**
```bash
wget https://openssl.org/source/openssl-3.6.2.tar.gz
tar -xvzf openssl-3.6.1.tar.gz
cd openssl-3.6.1
./Configure CC="/mingw64/bin/gcc.exe" CXX="/mingw64/bin/g++.exe" --prefix="D:/Labs_Crypto/openssl"
make -j $(nproc)
make install -j $(nproc)
```

### 2. Windows - MSVC (Visual Studio 2022)
**Prerequisites Setup:**
1. Install Visual Studio 2019 or 2022 with the C++ workload (ensuring `cl.exe` is available).
2. Install Strawberry Perl and Netwide Assembler (NASM). Add their `bin` directories to your Windows Environment Variables `Path`.

**Compile Crypto++:**
1. Clone the Crypto++ repository.
2. Open the `.sln` file in Visual Studio.
3. Build the solution in `Release` mode to generate `cryptlib.lib` and `cryptopp.dll`.

**Compile OpenSSL (3.2.1 or 3.6.1):**
1. Extract the OpenSSL source code.
2. Open the **"x64 Native Tools Command Prompt for VS 2022"** (Run as Administrator).
3. Navigate to the extracted OpenSSL directory and configure the build:
   ```cmd
   perl Configure VC-WIN64A shared --prefix="D:\Labs_Crypto\Openssl321-VS"
   nmake clean
   nmake cl=/MP
   nmake test cl=/MP
   nmake install shared cl=/MP
   ```

### 3. Linux (Ubuntu LTS)
**Prerequisites Setup:**
```bash
sudo apt update
sudo apt install build-essential g++-10 gcc-10 cmake git wget
```

**Compile Crypto++:**
```bash
git clone https://github.com/weidai11/cryptopp
cd cryptopp
make -j $(nproc)
sudo make install
```

**Compile OpenSSL (3.6.1):**
```bash
wget https://www.openssl.org/source/openssl-3.6.1.tar.gz
tar -xvzf openssl-3.6.1.tar.gz
cd openssl-3.6.1
./config --prefix="/home/ngoctu/Desktop/Openassl/openssl321" openssldir="/home/ngoctu/Desktop/Openassl/openssl321"
sudo make -j $(nproc)
sudo make test -j $(nproc)
sudo make install -j $(nproc)
```

## Build Commands
This project supports out-of-source builds using CMake. The commands are identical for both Windows and Linux environments.

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

## Example CLI Usage
All lab tools follow a uniform CLI standard:

**Symmetric Encryption (Lab 1 & 2):**
```bash
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin --aead
aestool decrypt --mode gcm --key key.bin --in ct.bin --out msg.txt --aead
```

**RSA & Hybrid Encryption (Lab 3):**
```bash
rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem
rsatool encrypt --in msg.bin --pub pub.pem --out ct.bin
```

**Hashing (Lab 4):**
```bash
hashtool --algo sha256 --in file.bin
hashtool --algo shake256 --outlen 64 --in file.bin
```

**Digital Signatures (Lab 5 & 6):**
```bash
sigtool sign --algo ecdsa-p256 --in msg.bin --out sig.bin --hash sha256
pqtool keygen --algo mldsa-44 --pub pub.pem --priv priv.pem
```

**Testing against NIST KATs:**
```bash
aestool --kat path/to/vectors.json
```

## Known Limitations
* **RSA Plaintext Limit:** Direct RSA-OAEP encryption is strictly bounded by `k - 2hLen - 2` bytes. For larger files, the system automatically falls back to hybrid envelope encryption (AES-GCM + RSA).
* **ECB Mode Restrictions:** ECB mode is blocked by default for files >16 KiB. To force ECB, the `--allow-ecb` flag must be explicitly passed.
* **CTR Mode Tampering:** As CTR mode turns AES into a stream cipher, tampering without an authentication tag (AEAD) will result in corrupted plaintext but no explicit failure alert.
* **Lab 4 Exploits:** The MD5 collision and length-extension attack tools are implemented purely for educational demonstration within offline environments. Do not execute against live services.