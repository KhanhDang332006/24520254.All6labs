#!/bin/bash

echo "==================================================="
echo "      Xay dung va khoi chay Lab Mat Ma Hoc       "
echo "==================================================="

# 1. Kiem tra va cai dat thu vien Python
echo "[*] Kiem tra thu vien Python (PySide6)..."
# Dung pip3 tren Linux
pip3 install -r ../gui/requirements.txt
if [ $? -ne 0 ]; then
    echo "[!] Loi khi cai dat thu vien Python. Vui long kiem tra lai pip3."
    exit 1
fi

# 2. Build CMake
echo "[*] Dang tao thu muc build bang CMake..."
if [ -z "$CRYPTOPP_ROOT" ]; then
    cmake -S .. -B ../build -DCMAKE_BUILD_TYPE=Release
else
    cmake -S .. -B ../build -DCMAKE_BUILD_TYPE=Release -DCRYPTOPP_ROOT="$CRYPTOPP_ROOT"
fi

echo "[*] Dang bien dich du an..."
# Dung nproc de lay so core CPU giup build nhanh hon
cmake --build ../build --config Release -j$(nproc)
if [ $? -ne 0 ]; then
    echo "[!] Loi bien dich C++. Kiem tra lai ma nguon hoac duong dan thu vien."
    exit 1
fi

# 3. Chay GUI
echo "[*] Bien dich thanh cong! Dang mo giao dien..."
cd ../gui
python3 rsaTool_gui.py