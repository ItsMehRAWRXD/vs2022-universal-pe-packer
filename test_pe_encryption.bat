@echo off
echo ============================================
echo Testing PE Encryption System
echo ============================================

REM Check if g++ is available
g++ --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: g++ not found! Please install MinGW-w64 or MSYS2
    echo Download from: https://www.msys2.org/
    pause
    exit /b 1
)

echo [1/4] Building PE Encryptor...
g++ -std=c++11 -O2 -static simple_pe_encryptor.cpp -o pe_encryptor.exe
if %errorlevel% neq 0 (
    echo [-] Failed to build PE encryptor!
    pause
    exit /b 1
)
echo [+] PE Encryptor built successfully!

echo.
echo [2/4] Building test program...
g++ -std=c++11 -O2 test_program.cpp -o test_program.exe
if %errorlevel% neq 0 (
    echo [-] Failed to build test program!
    pause
    exit /b 1
)
echo [+] Test program built successfully!

echo.
echo [3/4] Encrypting test program...
pe_encryptor.exe test_program.exe encrypted_test.exe
if %errorlevel% neq 0 (
    echo [-] Failed to encrypt test program!
    pause
    exit /b 1
)
echo [+] Test program encrypted successfully!

echo.
echo [4/4] Testing encrypted program...
echo [+] Running original program first:
echo ----------------------------------------
test_program.exe

echo.
echo [+] Now running encrypted program:
echo ----------------------------------------
encrypted_test.exe

echo.
echo ============================================
echo Test Complete!
echo ============================================
echo Files created:
echo - pe_encryptor.exe    (The encryptor tool)
echo - test_program.exe    (Original test program)
echo - encrypted_test.exe  (Encrypted version)
echo.
echo You can now use pe_encryptor.exe to encrypt any PE file:
echo   pe_encryptor.exe input.exe output.exe
echo.
pause