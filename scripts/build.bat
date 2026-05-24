@echo off
echo ===================================================
echo      Xay dung va khoi chay Lab Mat Ma Hoc
echo ===================================================

:: 1. Kiem tra va cai dat PySide6
echo [*] Kiem tra thu vien Python (PySide6)...
pip install -r ..\gui\requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [!] Loi khi cai dat thu vien Python. Kiem tra lai pip.
    pause
    exit /b %ERRORLEVEL%
)

:: 2. Build CMake
echo [*] Dang tao thu muc build bang CMake...
:: Kiem tra xem nguoi dung co thiet lap bien moi truong CRYPTOPP_ROOT chua
if "%CRYPTOPP_ROOT%"=="" (
    echo [*] Chu y: Khong tim thay bien moi truong CRYPTOPP_ROOT.
    echo [*] CMake se tim trong cac duong dan mac dinh cua he thong.
    cmake -S .. -B ..\build -DCMAKE_BUILD_TYPE=Release
) else (
    echo [*] Su dung CRYPTOPP_ROOT: %CRYPTOPP_ROOT%
    cmake -S .. -B ..\build -DCMAKE_BUILD_TYPE=Release -DCRYPTOPP_ROOT="%CRYPTOPP_ROOT%"
)

echo [*] Dang bien dich du an...
cmake --build ..\build --config Release
if %ERRORLEVEL% neq 0 (
    echo [!] Loi bien dich C++. Kiem tra lai ma nguon hoac duong dan thu vien.
    pause
    exit /b %ERRORLEVEL%
)

:: 3. Chay GUI
echo [*] Bien dich thanh cong! Dang mo giao dien...
cd ..\gui
python rsaTool_gui.py
pause