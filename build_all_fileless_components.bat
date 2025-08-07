@echo off
echo Advanced Fileless Execution Components - Complete Build Script
echo =============================================================

echo.
echo Building all fileless execution components...
echo.

REM Check for Visual Studio compiler
where cl >nul 2>&1
if %errorlevel% equ 0 (
    echo Found Visual Studio compiler
    echo Building with Visual Studio...
    echo.
    
    REM Build triple assembly stub
    echo [1/5] Building triple assembly stub...
    cl /std:c++17 /O2 /MT /EHsc ^
       fileless_triple_asm_stub.cpp ^
       /Fe:fileless_triple_asm_stub.exe ^
       /link psapi.lib
    if %errorlevel% equ 0 (
        echo ✓ Triple assembly stub built successfully
    ) else (
        echo ✗ Triple assembly stub build failed
    )
    
    REM Build enhanced fileless integration
    echo [2/5] Building enhanced fileless integration...
    cl /std:c++17 /O2 /MT /EHsc ^
       enhanced_fileless_integration.cpp ^
       /Fe:enhanced_fileless_integration.exe ^
       /link psapi.lib wincrypt.lib
    if %errorlevel% equ 0 (
        echo ✓ Enhanced fileless integration built successfully
    ) else (
        echo ✗ Enhanced fileless integration build failed
    )
    
    REM Build simple fileless execution
    echo [3/5] Building simple fileless execution...
    cl /std:c++17 /O2 /MT /EHsc ^
       fileless_execution_simple.cpp ^
       /Fe:fileless_execution_simple.exe
    if %errorlevel% equ 0 (
        echo ✓ Simple fileless execution built successfully
    ) else (
        echo ✗ Simple fileless execution build failed
    )
    
    REM Build advanced stealth stub
    echo [4/5] Building advanced stealth stub...
    cl /std:c++17 /O2 /MT /EHsc ^
       advanced_stealth_stub.cpp ^
       /Fe:advanced_stealth_stub.exe ^
       /link psapi.lib
    if %errorlevel% equ 0 (
        echo ✓ Advanced stealth stub built successfully
    ) else (
        echo ✗ Advanced stealth stub build failed
    )
    
    REM Build test fileless execution
    echo [5/5] Building test fileless execution...
    cl /std:c++17 /O2 /MT /EHsc ^
       test_fileless_execution.cpp ^
       /Fe:test_fileless_execution.exe
    if %errorlevel% equ 0 (
        echo ✓ Test fileless execution built successfully
    ) else (
        echo ✗ Test fileless execution build failed
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
        
        REM Build triple assembly stub
        echo [1/5] Building triple assembly stub...
        g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
            fileless_triple_asm_stub.cpp ^
            -o fileless_triple_asm_stub.exe ^
            -lpsapi
        if %errorlevel% equ 0 (
            echo ✓ Triple assembly stub built successfully
        ) else (
            echo ✗ Triple assembly stub build failed
        )
        
        REM Build enhanced fileless integration
        echo [2/5] Building enhanced fileless integration...
        g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
            enhanced_fileless_integration.cpp ^
            -o enhanced_fileless_integration.exe ^
            -lpsapi -lcrypt32
        if %errorlevel% equ 0 (
            echo ✓ Enhanced fileless integration built successfully
        ) else (
            echo ✗ Enhanced fileless integration build failed
        )
        
        REM Build simple fileless execution
        echo [3/5] Building simple fileless execution...
        g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
            fileless_execution_simple.cpp ^
            -o fileless_execution_simple.exe
        if %errorlevel% equ 0 (
            echo ✓ Simple fileless execution built successfully
        ) else (
            echo ✗ Simple fileless execution build failed
        )
        
        REM Build advanced stealth stub
        echo [4/5] Building advanced stealth stub...
        g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
            advanced_stealth_stub.cpp ^
            -o advanced_stealth_stub.exe ^
            -lpsapi
        if %errorlevel% equ 0 (
            echo ✓ Advanced stealth stub built successfully
        ) else (
            echo ✗ Advanced stealth stub build failed
        )
        
        REM Build test fileless execution
        echo [5/5] Building test fileless execution...
        g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
            test_fileless_execution.cpp ^
            -o test_fileless_execution.exe
        if %errorlevel% equ 0 (
            echo ✓ Test fileless execution built successfully
        ) else (
            echo ✗ Test fileless execution build failed
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

if exist fileless_triple_asm_stub.exe (
    echo ✓ fileless_triple_asm_stub.exe - Advanced triple assembly execution
) else (
    echo ✗ fileless_triple_asm_stub.exe - Build failed
)

if exist enhanced_fileless_integration.exe (
    echo ✓ enhanced_fileless_integration.exe - Framework integration engine
) else (
    echo ✗ enhanced_fileless_integration.exe - Build failed
)

if exist fileless_execution_simple.exe (
    echo ✓ fileless_execution_simple.exe - Simple fileless execution
) else (
    echo ✗ fileless_execution_simple.exe - Build failed
)

if exist advanced_stealth_stub.exe (
    echo ✓ advanced_stealth_stub.exe - Advanced stealth execution
) else (
    echo ✗ advanced_stealth_stub.exe - Build failed
)

if exist test_fileless_execution.exe (
    echo ✓ test_fileless_execution.exe - Fileless execution test suite
) else (
    echo ✗ test_fileless_execution.exe - Build failed
)

echo.
echo ================================================
echo Usage Examples:
echo ================================================

if exist fileless_triple_asm_stub.exe (
    echo Test triple assembly: fileless_triple_asm_stub.exe
)

if exist enhanced_fileless_integration.exe (
    echo Framework integration: enhanced_fileless_integration.exe bitminer triple_asm output.cpp
)

if exist fileless_execution_simple.exe (
    echo Simple execution: fileless_execution_simple.exe
)

if exist advanced_stealth_stub.exe (
    echo Stealth execution: advanced_stealth_stub.exe
)

if exist test_fileless_execution.exe (
    echo Test suite: test_fileless_execution.exe
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
echo ✓ Framework Integration
echo ✓ Payload Type Support (bitminer, admin, malware, custom)
echo ✓ Multiple Execution Methods
echo ✓ Anti-Detection Features
echo ✓ Timing-Based Anti-Debug
echo ✓ Process Injection Detection
echo ✓ Assembly Stub Generation
echo ✓ Complete Package Generation
echo.

pause