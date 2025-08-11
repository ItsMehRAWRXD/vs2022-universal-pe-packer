@echo off
echo Simple PE Encryptor - Windows Build Script
echo ==========================================

REM Check for Visual Studio compiler
where cl >nul 2>&1
if %errorlevel% equ 0 (
    echo Found Visual Studio compiler
    echo Building with Visual Studio...
    
    cl /std:c++17 /O2 /MT /EHsc ^
       simple_pe_encryptor.cpp ^
       /Fe:simple_pe_encryptor.exe ^
       /link crypt32.lib
    
    if %errorlevel% equ 0 (
        echo ✓ Build successful with Visual Studio!
        echo.
        echo Usage:
        echo simple_pe_encryptor.exe <input_file> <output_file>
        echo.
        echo Example:
        echo simple_pe_encryptor.exe malware.exe encrypted_malware.bin
        echo.
        echo Features:
        echo - PE header manipulation
        echo - AES-256 encryption
        echo - Timestamp randomization
        echo - Rich header removal
    ) else (
        echo ✗ Visual Studio build failed
        goto try_mingw
    )
) else (
    echo Visual Studio compiler not found, trying MinGW...
    goto try_mingw
)

:try_mingw
REM Check for MinGW compiler
where g++ >nul 2>&1
if %errorlevel% equ 0 (
    echo Found MinGW compiler
    echo Building with MinGW...
    
    g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
        simple_pe_encryptor.cpp ^
        -o simple_pe_encryptor.exe ^
        -lcrypt32
    
    if %errorlevel% equ 0 (
        echo ✓ Build successful with MinGW!
        echo.
        echo Usage:
        echo simple_pe_encryptor.exe <input_file> <output_file>
        echo.
        echo Example:
        echo simple_pe_encryptor.exe malware.exe encrypted_malware.bin
        echo.
        echo Features:
        echo - PE header manipulation
        echo - AES-256 encryption
        echo - Timestamp randomization
        echo - Rich header removal
    ) else (
        echo ✗ MinGW build failed
        echo.
        echo Please install either:
        echo 1. Visual Studio Build Tools
        echo 2. MinGW-w64
        echo.
        echo For Visual Studio: https://visualstudio.microsoft.com/downloads/
        echo For MinGW: https://www.mingw-w64.org/downloads/
    )
) else (
    echo No C++ compiler found!
    echo.
    echo Please install either:
    echo 1. Visual Studio Build Tools
    echo 2. MinGW-w64
    echo.
    echo For Visual Studio: https://visualstudio.microsoft.com/downloads/
    echo For MinGW: https://www.mingw-w64.org/downloads/
)

pause