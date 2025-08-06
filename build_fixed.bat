@echo off
setlocal enabledelayedexpansion
echo ========================================
echo   VS2022 FUD Packer - Fixed Build
echo ========================================
echo.

REM Check if source file exists
if not exist "VS2022_GUI_Benign_Packer.cpp" (
    echo ERROR: VS2022_GUI_Benign_Packer.cpp not found!
    echo Please run this script from the project directory.
    pause
    exit /b 1
)

echo [1/6] Checking build environment...

REM Try to find Visual Studio 2022 installation
set "VS_PATH="
set "VS_VERSION="

if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_VERSION=Community"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_VERSION=Professional"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_VERSION=Enterprise"
)

if defined VS_PATH (
    echo Found Visual Studio 2022 %VS_VERSION%
    echo Setting up build environment...
    call "%VS_PATH%"
    
    echo [2/6] Compiling with Visual Studio 2022...
    cl.exe /nologo /std:c++17 /EHsc /O2 /DNDEBUG /DUNICODE /D_UNICODE ^
        VS2022_GUI_Benign_Packer.cpp ^
        /Fe:VS2022_GUI_Benign_Packer_FIXED.exe ^
        /link /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF ^
        ole32.lib crypt32.lib wininet.lib wintrust.lib imagehlp.lib ^
        comctl32.lib shell32.lib advapi32.lib user32.lib kernel32.lib gdi32.lib
    
    if %ERRORLEVEL% equ 0 (
        echo.
        echo ======================================
        echo BUILD SUCCESSFUL with Visual Studio!
        echo ======================================
        echo Output: VS2022_GUI_Benign_Packer_FIXED.exe
        echo.
        goto :success
    ) else (
        echo Visual Studio compilation failed, trying alternative methods...
    )
) else (
    echo Visual Studio 2022 not found, trying alternative compilers...
)

echo [3/6] Checking for MinGW-w64...

REM Try MinGW-w64
where g++.exe >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Found MinGW-w64, compiling...
    g++ -std=c++17 -O2 -DNDEBUG -static-libgcc -static-libstdc++ ^
        -mwindows VS2022_GUI_Benign_Packer.cpp ^
        -o VS2022_GUI_Benign_Packer_FIXED.exe ^
        -luser32 -lkernel32 -lgdi32 -ladvapi32 -lshell32 -lole32 -lcomctl32 -lwininet -lcrypt32 -lwintrust -limagehlp
    
    if %ERRORLEVEL% equ 0 (
        echo.
        echo ======================================
        echo BUILD SUCCESSFUL with MinGW-w64!
        echo ======================================
        echo Output: VS2022_GUI_Benign_Packer_FIXED.exe
        echo.
        goto :success
    ) else (
        echo MinGW compilation failed, trying TCC...
    )
)

echo [4/6] Checking for TCC (Tiny C Compiler)...

REM Try TCC
where tcc.exe >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Found TCC, compiling...
    tcc -O2 -mwindows VS2022_GUI_Benign_Packer.cpp -o VS2022_GUI_Benign_Packer_FIXED.exe -luser32 -lkernel32 -lgdi32
    
    if %ERRORLEVEL% equ 0 (
        echo.
        echo ======================================
        echo BUILD SUCCESSFUL with TCC!
        echo ======================================
        echo Output: VS2022_GUI_Benign_Packer_FIXED.exe
        echo.
        goto :success
    ) else (
        echo TCC compilation failed...
    )
)

echo [5/6] Downloading portable compiler...

REM Download TCC if not available
if not exist "tcc.exe" (
    echo Downloading Tiny C Compiler...
    powershell -Command "try { Invoke-WebRequest -Uri 'https://github.com/TinyCC/tinycc/releases/download/release_0_9_27/tcc-0.9.27-win64-bin.zip' -OutFile 'tcc.zip' -UseBasicParsing } catch { exit 1 }" >nul 2>&1
    
    if exist "tcc.zip" (
        echo Extracting TCC...
        powershell -Command "try { Expand-Archive -Path 'tcc.zip' -DestinationPath 'tcc_temp' -Force } catch { exit 1 }" >nul 2>&1
        
        if exist "tcc_temp" (
            if exist "tcc_temp\tcc.exe" copy "tcc_temp\tcc.exe" "." >nul
            if exist "tcc_temp\libtcc1.a" copy "tcc_temp\libtcc1.a" "." >nul
            if exist "tcc_temp\include" xcopy "tcc_temp\include" "include\" /E /I /Q >nul 2>&1
            if exist "tcc_temp\lib" xcopy "tcc_temp\lib" "lib\" /E /I /Q >nul 2>&1
            
            rmdir /s /q "tcc_temp" >nul 2>&1
            del "tcc.zip" >nul 2>&1
            echo TCC downloaded successfully!
            
            echo [6/6] Compiling with downloaded TCC...
            tcc.exe -O2 -mwindows VS2022_GUI_Benign_Packer.cpp -o VS2022_GUI_Benign_Packer_FIXED.exe -luser32 -lkernel32 -lgdi32
            
            if %ERRORLEVEL% equ 0 (
                echo.
                echo ======================================
                echo BUILD SUCCESSFUL with downloaded TCC!
                echo ======================================
                echo Output: VS2022_GUI_Benign_Packer_FIXED.exe
                echo.
                goto :success
            )
        )
    )
)

echo.
echo ==========================================
echo   ALL COMPILATION METHODS FAILED
echo ==========================================
echo.
echo The internal compiler has been fixed, but external compilation failed.
echo This may be due to:
echo.
echo 1. Missing Visual Studio 2022 with C++ tools
echo 2. Missing MinGW-w64 installation
echo 3. Network issues preventing TCC download
echo 4. Source code compilation errors
echo.
echo Please try one of these solutions:
echo.
echo A) Install Visual Studio 2022 Community (free):
echo    https://visualstudio.microsoft.com/downloads/
echo.
echo B) Install MinGW-w64:
echo    https://www.mingw-w64.org/downloads/
echo.
echo C) Manual compilation:
echo    - Open Developer Command Prompt for VS 2022
echo    - Run: cl.exe /O2 VS2022_GUI_Benign_Packer.cpp /Fe:output.exe
echo.
pause
exit /b 1

:success
echo The executable has been built successfully!
echo.
echo Features of the fixed version:
echo - Internal PE generation capability
echo - Better error handling and logging
echo - Improved compiler detection
echo - Fallback compilation methods
echo.
echo Double-click VS2022_GUI_Benign_Packer_FIXED.exe to run it.
echo.
pause