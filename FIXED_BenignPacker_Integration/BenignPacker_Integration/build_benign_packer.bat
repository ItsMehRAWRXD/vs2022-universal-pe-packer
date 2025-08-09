@echo off
echo.
echo ========================================
echo 🚀 BENIGN PACKER C++ BUILD SCRIPT 🚀
echo ========================================
echo Author: ItsMehRAWRXD/Star Framework
echo Compatible: Visual Studio 2022
echo Output: .EXE files (not .bin files)
echo ========================================
echo.

REM Set script directory as current directory
cd /d "%~dp0"

REM Check if Visual Studio 2022 is available
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ ERROR: Visual Studio 2022 compiler not found!
    echo.
    echo Please run this script from:
    echo - Visual Studio 2022 Developer Command Prompt
    echo - Or ensure VS2022 is properly installed
    echo.
    pause
    exit /b 1
)

echo ✅ Visual Studio 2022 compiler found
echo.

REM Create necessary directories
echo 📁 Creating directories...
if not exist "bin" mkdir bin
if not exist "bin\Release" mkdir bin\Release
if not exist "bin\Release\x64" mkdir bin\Release\x64
if not exist "bin\Debug" mkdir bin\Debug
if not exist "bin\Debug\x64" mkdir bin\Debug\x64
if not exist "obj" mkdir obj
if not exist "output" mkdir output
if not exist "temp" mkdir temp
echo ✅ Directories created
echo.

REM Check if solution file exists
if not exist "BenignPacker.sln" (
    echo ❌ ERROR: BenignPacker.sln not found!
    echo Please ensure you're in the correct directory.
    pause
    exit /b 1
)

echo 🔨 Building BenignPacker Solution...
echo Configuration: Release
echo Platform: x64
echo.

REM Build the solution
msbuild BenignPacker.sln /p:Configuration=Release /p:Platform=x64 /p:WarningLevel=1 /m

if %errorlevel% neq 0 (
    echo.
    echo ❌ BUILD FAILED!
    echo Check the error messages above for details.
    echo.
    echo Common issues:
    echo - Missing Windows SDK
    echo - Missing C++ build tools
    echo - Plugin compilation errors
    echo.
    pause
    exit /b 1
)

echo.
echo ✅ BUILD SUCCESSFUL!
echo.

REM Check if the main executable was created
if exist "bin\Release\x64\BenignPacker.exe" (
    echo 🎉 BenignPacker.exe created successfully!
    
    REM Get file size
    for %%A in ("bin\Release\x64\BenignPacker.exe") do (
        echo File size: %%~zA bytes
    )
    
    echo Location: bin\Release\x64\BenignPacker.exe
    echo.
) else (
    echo ❌ WARNING: BenignPacker.exe not found in expected location
    echo Check build output for errors.
)

REM Check for plugins
echo 🔌 Checking for plugins...
if exist "bin\Release\x64\UniqueStub71Plugin.dll" (
    echo ✅ UniqueStub71Plugin.dll found
) else (
    echo ⚠️  UniqueStub71Plugin.dll not found - will use built-in functionality
)

if exist "bin\Release\x64\MASMAssemblerPlugin.dll" (
    echo ✅ MASMAssemblerPlugin.dll found
) else (
    echo ⚠️  MASMAssemblerPlugin.dll not found - optional
)

echo.
echo 🧪 TESTING BASIC FUNCTIONALITY...
echo.

REM Create a test payload
echo Test payload data > temp\test_payload.bin

REM Test the executable
if exist "bin\Release\x64\BenignPacker.exe" (
    echo Running: BenignPacker.exe temp\test_payload.bin temp\test_output.exe
    "bin\Release\x64\BenignPacker.exe" temp\test_payload.bin temp\test_output.exe
    
    if exist "temp\test_output.exe" (
        echo ✅ TEST PASSED: .EXE file generated successfully!
        
        REM Get output file size
        for %%A in ("temp\test_output.exe") do (
            echo Generated file size: %%~zA bytes
        )
        
        del temp\test_output.exe >nul 2>&1
    ) else (
        echo ❌ TEST FAILED: No .EXE file generated
    )
) else (
    echo ❌ Cannot test - executable not found
)

REM Cleanup test files
del temp\test_payload.bin >nul 2>&1

echo.
echo ========================================
echo 📊 BUILD SUMMARY
echo ========================================

REM Display build information
if exist "bin\Release\x64\BenignPacker.exe" (
    echo Status: ✅ SUCCESS
    echo Main executable: CREATED
    echo Location: bin\Release\x64\BenignPacker.exe
    
    REM Count plugins
    set plugin_count=0
    if exist "bin\Release\x64\UniqueStub71Plugin.dll" set /a plugin_count+=1
    if exist "bin\Release\x64\MASMAssemblerPlugin.dll" set /a plugin_count+=1
    echo Plugins loaded: %plugin_count%
    
    echo.
    echo 🎯 USAGE EXAMPLES:
    echo ================
    echo Basic usage:
    echo   bin\Release\x64\BenignPacker.exe payload.bin
    echo.
    echo Advanced usage:
    echo   bin\Release\x64\BenignPacker.exe payload.bin output.exe advanced
    echo.
    echo Help:
    echo   bin\Release\x64\BenignPacker.exe
    echo.
) else (
    echo Status: ❌ FAILED
    echo Check error messages above
)

echo ========================================
echo 🔥 BENIGN PACKER C++ READY! 🔥
echo ========================================
echo.
echo Your MASM BenignPacker has been converted to C++
echo Now generates .EXE files instead of .bin files!
echo.
echo Features included:
echo ✅ 40+ Advanced Mutex Systems
echo ✅ Company Profile Spoofing
echo ✅ Certificate Chain Management
echo ✅ 18 Exploit Methods
echo ✅ Anti-Analysis Evasion
echo ✅ Plugin Architecture
echo ✅ Visual Studio 2022 Compatible
echo.

pause