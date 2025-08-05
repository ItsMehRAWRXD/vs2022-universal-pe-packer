@echo off
echo ========================================
echo VS2022 Universal PE Packer - Visual Studio 2022 Build
echo ========================================
echo.

echo [1/3] Checking for Visual Studio 2022...
where cl >nul 2>&1
if %errorlevel% equ 0 (
    echo [SUCCESS] Found Visual Studio compiler
    echo [2/3] Compiling with Visual Studio 2022...
    
    cl /std:c++17 /O2 /DWIN32_LEAN_AND_MEAN /MT VS2022_MenuEncryptor_Clean.cpp /Fe:VS2022_Packer.exe wininet.lib advapi32.lib shell32.lib
    if %errorlevel% equ 0 (
        echo [SUCCESS] Visual Studio compilation successful!
        echo [INFO] Output: VS2022_Packer.exe
        echo [INFO] Size: 
        dir VS2022_Packer.exe | find "VS2022_Packer.exe"
    ) else (
        echo [ERROR] Visual Studio compilation failed
        echo [INFO] Trying alternative compilation...
        
        cl /std:c++17 /O2 /DWIN32_LEAN_AND_MEAN VS2022_MenuEncryptor_Clean.cpp /Fe:VS2022_Packer.exe wininet.lib advapi32.lib
        if %errorlevel% equ 0 (
            echo [SUCCESS] Alternative compilation successful!
        ) else (
            echo [ERROR] All compilation attempts failed
        )
    )
) else (
    echo [ERROR] Visual Studio cl.exe not found
    echo [INFO] Please ensure Visual Studio 2022 is installed and Developer Command Prompt is used
    echo [INFO] Or run: "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)

echo.
echo [3/3] Build Summary:
echo ========================================
if exist VS2022_Packer.exe (
    echo [SUCCESS] Build: VS2022_Packer.exe
    dir VS2022_Packer.exe | find "VS2022_Packer.exe"
    echo.
    echo [INFO] Features available:
    echo   * 15 different encryption modes
    echo   * ChaCha20, AES, Triple-layer encryption
    echo   * URL download and packing services
    echo   * Drag & drop support
    echo   * MASM assembly stub generation
    echo   * Polymorphic code generation
    echo   * Windows CryptoAPI integration
    echo   * Enhanced WinINet HTTP downloads
) else (
    echo [ERROR] Build failed
    echo.
    echo [TROUBLESHOOTING]
    echo 1. Ensure Visual Studio 2022 is installed
    echo 2. Run from Developer Command Prompt
    echo 3. Check that cl.exe is in PATH
    echo 4. Verify Windows SDK is installed
)

echo.
echo ========================================
echo Usage Instructions:
echo ========================================
echo Interactive Mode: VS2022_Packer.exe
echo Drag & Drop: Drag files onto VS2022_Packer.exe
echo Command Line: VS2022_Packer.exe file1.exe file2.dll
echo.
echo For full functionality, use the complete VS2022_MenuEncryptor.cpp file
echo This clean version provides basic encryption and menu framework
echo.
pause