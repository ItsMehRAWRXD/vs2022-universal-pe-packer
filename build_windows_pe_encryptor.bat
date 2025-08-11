@echo off
echo Cross-Platform PE Encryptor - Windows Build Script
echo ==================================================

REM Check for Visual Studio compiler
where cl >nul 2>&1
if %errorlevel% equ 0 (
    echo Found Visual Studio compiler
    echo Building with Visual Studio...
    
    cl /std:c++17 /O2 /MT /EHsc ^
       VS2022_Ultimate_Stealth_Fixed.cpp ^
       /Fe:pe_encryptor.exe ^
       /link wininet.lib advapi32.lib crypt32.lib psapi.lib imagehlp.lib wintrust.lib
    
    if %errorlevel% equ 0 (
        echo ✓ Build successful with Visual Studio!
        echo.
        echo Usage:
        echo pe_encryptor.exe
        echo.
        echo Features:
        echo - PE header manipulation
        echo - Advanced encryption
        echo - Timestamp randomization
        echo - Rich header removal
        echo - Legitimate signature generation
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
        VS2022_Ultimate_Stealth_Fixed.cpp ^
        -o pe_encryptor.exe ^
        -lwininet -ladvapi32 -lcrypt32 -lpsapi -limagehlp -lwintrust
    
    if %errorlevel% equ 0 (
        echo ✓ Build successful with MinGW!
        echo.
        echo Usage:
        echo pe_encryptor.exe
        echo.
        echo Features:
        echo - PE header manipulation
        echo - Advanced encryption
        echo - Timestamp randomization
        echo - Rich header removal
        echo - Legitimate signature generation
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