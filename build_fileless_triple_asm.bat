@echo off
echo Advanced Fileless Triple Assembly Stub - Build Script
echo ====================================================

echo.
echo Building advanced fileless execution stub...
echo.

REM Check for Visual Studio compiler
where cl >nul 2>&1
if %errorlevel% equ 0 (
    echo Found Visual Studio compiler
    echo Building with Visual Studio...
    echo.
    
    REM Build the advanced fileless stub
    cl /std:c++17 /O2 /MT /EHsc ^
       fileless_triple_asm_stub.cpp ^
       /Fe:fileless_triple_asm_stub.exe ^
       /link psapi.lib
    
    if %errorlevel% equ 0 (
        echo ✓ Advanced fileless stub built successfully with Visual Studio!
        echo.
        echo Features:
        echo - Triple layer assembly execution
        echo - Advanced anti-debugging techniques
        echo - Dynamic API resolution
        echo - Memory protection bypass
        echo - Instruction cache manipulation
        echo - Cross-platform compatibility
        echo - Polymorphic variable generation
        echo - Stealth execution engine
        echo.
        echo Usage: fileless_triple_asm_stub.exe
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
    
    REM Build the advanced fileless stub
    g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
        fileless_triple_asm_stub.cpp ^
        -o fileless_triple_asm_stub.exe ^
        -lpsapi
    
    if %errorlevel% equ 0 (
        echo ✓ Advanced fileless stub built successfully with MinGW!
        echo.
        echo Features:
        echo - Triple layer assembly execution
        echo - Advanced anti-debugging techniques
        echo - Dynamic API resolution
        echo - Memory protection bypass
        echo - Instruction cache manipulation
        echo - Cross-platform compatibility
        echo - Polymorphic variable generation
        echo - Stealth execution engine
        echo.
        echo Usage: fileless_triple_asm_stub.exe
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
echo Advanced Fileless Execution Features:
echo ================================================
echo ✓ Triple Layer Assembly Execution
echo ✓ Advanced Anti-Debugging Techniques
echo ✓ Dynamic API Resolution
echo ✓ Memory Protection Bypass
echo ✓ Instruction Cache Manipulation
echo ✓ Cross-Platform Compatibility
echo ✓ Polymorphic Variable Generation
echo ✓ Stealth Execution Engine
echo ✓ Assembly Stub Generation
echo ✓ Process Injection Detection
echo ✓ Timing-Based Anti-Debug
echo ✓ PEB BeingDebugged Check
echo ✓ Debugger Process Detection
echo ✓ Linux ptrace Detection
echo ✓ /proc/self/status Analysis
echo.

pause