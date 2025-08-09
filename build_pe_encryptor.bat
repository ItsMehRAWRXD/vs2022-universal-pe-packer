@echo off
echo Building Simple PE Encryptor...

REM Check if g++ is available
g++ --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: g++ not found! Please install MinGW-w64 or MSYS2
    echo Download from: https://www.msys2.org/
    pause
    exit /b 1
)

echo [+] Compiling PE Encryptor...
g++ -std=c++11 -O2 -static -s simple_pe_encryptor.cpp -o pe_encryptor.exe

if %errorlevel% equ 0 (
    echo [+] Build successful! Created pe_encryptor.exe
    echo.
    echo Usage Examples:
    echo   pe_encryptor.exe calc.exe encrypted_calc.exe
    echo   pe_encryptor.exe notepad.exe encrypted_notepad.exe
    echo   pe_encryptor.exe yourfile.exe encrypted_yourfile.exe
    echo.
) else (
    echo [-] Build failed!
    pause
    exit /b 1
)

pause