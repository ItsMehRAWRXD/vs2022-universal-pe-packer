@echo off
echo ====================================
echo PE Packer Suite - Build from Source
echo ====================================
echo.

echo [1/4] Compiling generators...
g++ -std=c++17 -O2 -static -o test_pe_generator.exe test_pe_generator.cpp
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile test_pe_generator
    pause
    exit /b 1
)

g++ -std=c++17 -O2 -static -o stub_generator.exe stub_generator.cpp
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile stub_generator
    pause
    exit /b 1
)

g++ -std=c++17 -O2 -static -o mass_stub_generator.exe mass_stub_generator.cpp
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile mass_stub_generator
    pause
    exit /b 1
)
echo   ✓ Generators compiled successfully

echo.
echo [2/4] Compiling main tools...
g++ -std=c++17 -O2 -static -o encryptor.exe main.cpp pe_encryptor.cpp stealth_triple_encryptor.cpp
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile encryptor
    pause
    exit /b 1
)

g++ -std=c++17 -O2 -static -o comprehensive_tester.exe comprehensive_tester.cpp
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile comprehensive_tester
    pause
    exit /b 1
)

g++ -std=c++17 -O2 -static -o sample_test.exe sample_test.cpp
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile sample_test
    pause
    exit /b 1
)
echo   ✓ Main tools compiled successfully

echo.
echo [3/4] Generating PE test files...
test_pe_generator.exe
if %errorlevel% neq 0 (
    echo ERROR: Failed to generate PE test files
    pause
    exit /b 1
)
echo   ✓ 10 PE test files generated

echo.
echo [4/4] Generating stub variants...
echo   Generating 25 basic stubs...
stub_generator.exe
if %errorlevel% neq 0 (
    echo ERROR: Failed to generate basic stubs
    pause
    exit /b 1
)

echo   Generating 100 advanced stubs...
mass_stub_generator.exe
if %errorlevel% neq 0 (
    echo ERROR: Failed to generate advanced stubs
    pause
    exit /b 1
)
echo   ✓ 125 stub variants generated

echo.
echo ====================================
echo BUILD COMPLETE!
echo ====================================
echo.
echo Generated files:
echo   • 6 Tools (encryptor.exe, generators, testers)
echo   • 10 Test PE files (basic + complex)
echo   • 125 Stub variants (25 basic + 100 advanced)
echo   • Total: 141 executable files
echo.
echo Next steps:
echo   1. Run 'encryptor.exe help' for usage
echo   2. Test with 'sample_test.exe'
echo   3. Read README_USAGE.md for details
echo.
pause