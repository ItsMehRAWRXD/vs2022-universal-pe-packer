@echo off
echo Comprehensive PE Encryption Tools - Build Script
echo ================================================

echo.
echo Building all PE encryption tools...
echo.

REM Check for Visual Studio compiler
where cl >nul 2>&1
if %errorlevel% equ 0 (
    echo Found Visual Studio compiler
    echo Building with Visual Studio...
    echo.
    
    REM Build test program first
    echo [1/4] Building PE encryption test program...
    cl /std:c++17 /O2 /MT /EHsc test_pe_encryption.cpp /Fe:test_pe_encryption.exe
    if %errorlevel% equ 0 (
        echo ✓ Test program built successfully
    ) else (
        echo ✗ Test program build failed
    )
    
    REM Build simple PE encryptor
    echo [2/4] Building simple PE encryptor...
    cl /std:c++17 /O2 /MT /EHsc simple_pe_encryptor.cpp /Fe:simple_pe_encryptor.exe /link crypt32.lib
    if %errorlevel% equ 0 (
        echo ✓ Simple PE encryptor built successfully
    ) else (
        echo ✗ Simple PE encryptor build failed
    )
    
    REM Build advanced PE encryptor
    echo [3/4] Building advanced PE encryptor...
    cl /std:c++17 /O2 /MT /EHsc VS2022_Ultimate_Stealth_Fixed.cpp /Fe:advanced_pe_encryptor.exe /link wininet.lib advapi32.lib crypt32.lib psapi.lib imagehlp.lib wintrust.lib
    if %errorlevel% equ 0 (
        echo ✓ Advanced PE encryptor built successfully
    ) else (
        echo ✗ Advanced PE encryptor build failed
    )
    
    REM Build comprehensive framework
    echo [4/4] Building comprehensive framework...
    cl /std:c++17 /O2 /MT /EHsc comprehensive_pentest_framework.cpp /Fe:pentest_framework.exe /link wininet.lib ws2_32.lib
    if %errorlevel% equ 0 (
        echo ✓ Comprehensive framework built successfully
    ) else (
        echo ✗ Comprehensive framework build failed
    )
    
) else (
    echo Visual Studio compiler not found, trying MinGW...
    echo.
    
    REM Check for MinGW compiler
    where g++ >nul 2>&1
    if %errorlevel% equ 0 (
        echo Found MinGW compiler
        echo Building with MinGW...
        echo.
        
        REM Build test program first
        echo [1/4] Building PE encryption test program...
        g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ test_pe_encryption.cpp -o test_pe_encryption.exe
        if %errorlevel% equ 0 (
            echo ✓ Test program built successfully
        ) else (
            echo ✗ Test program build failed
        )
        
        REM Build simple PE encryptor
        echo [2/4] Building simple PE encryptor...
        g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ simple_pe_encryptor.cpp -o simple_pe_encryptor.exe -lcrypt32
        if %errorlevel% equ 0 (
            echo ✓ Simple PE encryptor built successfully
        ) else (
            echo ✗ Simple PE encryptor build failed
        )
        
        REM Build advanced PE encryptor
        echo [3/4] Building advanced PE encryptor...
        g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ VS2022_Ultimate_Stealth_Fixed.cpp -o advanced_pe_encryptor.exe -lwininet -ladvapi32 -lcrypt32 -lpsapi -limagehlp -lwintrust
        if %errorlevel% equ 0 (
            echo ✓ Advanced PE encryptor built successfully
        ) else (
            echo ✗ Advanced PE encryptor build failed
        )
        
        REM Build comprehensive framework
        echo [4/4] Building comprehensive framework...
        g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ comprehensive_pentest_framework.cpp -o pentest_framework.exe -lwininet -lws2_32 -lpthread
        if %errorlevel% equ 0 (
            echo ✓ Comprehensive framework built successfully
        ) else (
            echo ✗ Comprehensive framework build failed
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
        pause
        exit /b 1
    )
)

echo.
echo ================================================
echo Build Summary:
echo ================================================

if exist test_pe_encryption.exe (
    echo ✓ test_pe_encryption.exe - PE encryption test program
) else (
    echo ✗ test_pe_encryption.exe - Build failed
)

if exist simple_pe_encryptor.exe (
    echo ✓ simple_pe_encryptor.exe - Simple PE encryptor
) else (
    echo ✗ simple_pe_encryptor.exe - Build failed
)

if exist advanced_pe_encryptor.exe (
    echo ✓ advanced_pe_encryptor.exe - Advanced PE encryptor with stealth features
) else (
    echo ✗ advanced_pe_encryptor.exe - Build failed
)

if exist pentest_framework.exe (
    echo ✓ pentest_framework.exe - Comprehensive penetration testing framework
) else (
    echo ✗ pentest_framework.exe - Build failed
)

echo.
echo ================================================
echo Usage Examples:
echo ================================================

if exist test_pe_encryption.exe (
    echo Test PE encryption: test_pe_encryption.exe
)

if exist simple_pe_encryptor.exe (
    echo Simple encryption: simple_pe_encryptor.exe input.exe output.bin
)

if exist advanced_pe_encryptor.exe (
    echo Advanced encryption: advanced_pe_encryptor.exe
)

if exist pentest_framework.exe (
    echo Framework: pentest_framework.exe [target_url]
)

echo.
echo ================================================
echo Features Available:
echo ================================================
echo - PE header manipulation and validation
echo - AES-256 encryption with Windows CryptoAPI
echo - Timestamp randomization for stealth
echo - Rich header removal
echo - Legitimate signature generation
echo - CrowdStrike evasion techniques
echo - Comprehensive penetration testing tools
echo.

pause