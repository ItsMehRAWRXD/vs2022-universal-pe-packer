@echo off
echo ========================================
echo VS2022 Universal PE Packer - Windows Build
echo ========================================
echo.

echo [1/4] Checking for MinGW/TDM-GCC...
where g++ >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Found g++ compiler
    echo [2/4] Compiling with MinGW/TDM-GCC...
    g++ -std=c++17 -O2 -static -DWIN32_LEAN_AND_MEAN VS2022_MenuEncryptor.cpp -o VS2022_Packer.exe -lwininet -ladvapi32
    if %errorlevel% equ 0 (
        echo ✅ MinGW compilation successful!
        echo 📁 Output: VS2022_Packer.exe
    ) else (
        echo ❌ MinGW compilation failed
    )
) else (
    echo ⚠️  g++ not found, trying Visual Studio...
)

echo.
echo [3/4] Checking for Visual Studio...
where cl >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Found Visual Studio compiler
    echo [4/4] Compiling with Visual Studio...
    cl /std:c++17 /O2 /DWIN32_LEAN_AND_MEAN VS2022_MenuEncryptor.cpp /Fe:VS2022_Packer_VS.exe wininet.lib advapi32.lib
    if %errorlevel% equ 0 (
        echo ✅ Visual Studio compilation successful!
        echo 📁 Output: VS2022_Packer_VS.exe
    ) else (
        echo ❌ Visual Studio compilation failed
    )
) else (
    echo ⚠️  Visual Studio cl.exe not found
)

echo.
echo ========================================
echo Build Summary:
echo ========================================
if exist VS2022_Packer.exe (
    echo ✅ MinGW Build: VS2022_Packer.exe
    dir VS2022_Packer.exe | find "VS2022_Packer.exe"
) else (
    echo ❌ MinGW Build: Failed
)

if exist VS2022_Packer_VS.exe (
    echo ✅ Visual Studio Build: VS2022_Packer_VS.exe
    dir VS2022_Packer_VS.exe | find "VS2022_Packer_VS.exe"
) else (
    echo ❌ Visual Studio Build: Failed
)

echo.
echo ========================================
echo Usage Instructions:
echo ========================================
echo Interactive Mode: VS2022_Packer.exe
echo Drag & Drop: Drag files onto VS2022_Packer.exe
echo Command Line: VS2022_Packer.exe file1.exe file2.dll
echo.
echo Features:
echo • 15 different encryption modes
echo • ChaCha20, AES, Triple-layer encryption
echo • URL download and packing services
echo • Drag & drop support
echo • MASM assembly stub generation
echo • Polymorphic code generation
echo.
pause