@echo off
REM BlackMagii Suite - MinGW Build Script for Windows
REM 🎩✨ Easy build without Visual Studio!

echo ═══════════════════════════════════════════════════════════════
echo   🎩✨ BlackMagii Suite - MinGW-w64 Builder
echo   Building the Swiss Army Knife of Compilers!
echo ═══════════════════════════════════════════════════════════════
echo.

REM Check if MinGW is in PATH
where g++ >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ ERROR: MinGW-w64 not found in PATH!
    echo.
    echo Please install MinGW-w64 using one of these methods:
    echo.
    echo 1. MSYS2 (Recommended):
    echo    - Download from: https://www.msys2.org/
    echo    - After install, run: pacman -S mingw-w64-x86_64-gcc
    echo.
    echo 2. MinGW-w64 standalone:
    echo    - Download from: https://winlibs.com/
    echo    - Add bin folder to PATH
    echo.
    echo 3. TDM-GCC:
    echo    - Download from: https://jmeubank.github.io/tdm-gcc/
    echo.
    pause
    exit /b 1
)

REM Display compiler info
echo 📋 Compiler Information:
g++ --version | findstr "g++"
echo.

REM Create directories
echo 📁 Creating directories...
if not exist bin mkdir bin
if not exist obj mkdir obj
if not exist downloads mkdir downloads
echo.

REM Check for dependencies
echo 🔍 Checking dependencies...
set MISSING_DEPS=0

REM Check for zlib
echo | set /p="  - zlib.........."
if exist "C:\msys64\mingw64\include\zlib.h" (
    echo ✅ Found
) else if exist "%MINGW_HOME%\include\zlib.h" (
    echo ✅ Found
) else (
    echo ❌ Missing
    set MISSING_DEPS=1
)

REM Check for curl
echo | set /p="  - libcurl......."
if exist "C:\msys64\mingw64\include\curl\curl.h" (
    echo ✅ Found
) else if exist "%MINGW_HOME%\include\curl\curl.h" (
    echo ❌ Missing
    set MISSING_DEPS=1
)

echo.

if %MISSING_DEPS%==1 (
    echo.
    echo ⚠️  Some dependencies are missing!
    echo.
    echo Would you like to download pre-compiled libraries? (Y/N)
    set /p DOWNLOAD_LIBS=
    if /i "%DOWNLOAD_LIBS%"=="Y" (
        call :download_dependencies
    )
)

REM Main build menu
:menu
echo.
echo 🎯 What would you like to build?
echo ═══════════════════════════════════════
echo   1. Build ALL tools
echo   2. BlackMagii Compiler (Main)
echo   3. BlackMagii Enhanced (with tinyRAWR)
echo   4. BlackMamba IRC Bot
echo   5. Mobile Compiler Service
echo   6. VS2022 Menu Encryptor
echo   7. Clean build files
echo   8. Create installer package
echo   9. Exit
echo ═══════════════════════════════════════
echo.
set /p choice="Enter your choice (1-9): "

if "%choice%"=="1" goto build_all
if "%choice%"=="2" goto build_blackmagii
if "%choice%"=="3" goto build_enhanced
if "%choice%"=="4" goto build_blackmamba
if "%choice%"=="5" goto build_mobile
if "%choice%"=="6" goto build_encryptor
if "%choice%"=="7" goto clean
if "%choice%"=="8" goto package
if "%choice%"=="9" exit /b 0

echo Invalid choice!
goto menu

:build_all
echo.
echo 🚀 Building all BlackMagii tools...
echo ═══════════════════════════════════════
call :build_blackmagii_core
call :build_enhanced_core
call :build_blackmamba_core
call :build_mobile_core
call :build_encryptor_core
echo.
echo ✅ All tools built successfully!
echo 📁 Check the bin\ directory for executables
pause
goto menu

:build_blackmagii
echo.
echo 🎩 Building BlackMagii Compiler...
call :build_blackmagii_core
pause
goto menu

:build_enhanced
echo.
echo 🦖 Building BlackMagii Enhanced with tinyRAWR...
call :build_enhanced_core
pause
goto menu

:build_blackmamba
echo.
echo 🐍 Building BlackMamba IRC Bot...
call :build_blackmamba_core
pause
goto menu

:build_mobile
echo.
echo 📱 Building Mobile Compiler Service...
call :build_mobile_core
pause
goto menu

:build_encryptor
echo.
echo 🔐 Building VS2022 Menu Encryptor...
call :build_encryptor_core
pause
goto menu

:clean
echo.
echo 🧹 Cleaning build files...
del /q obj\*.o 2>nul
del /q obj\*.res 2>nul
del /q bin\*.exe 2>nul
echo ✅ Clean complete!
pause
goto menu

:package
echo.
echo 📦 Creating distribution package...
if not exist BlackMagii_Win64 mkdir BlackMagii_Win64
copy bin\*.exe BlackMagii_Win64\ >nul 2>nul
copy *.md BlackMagii_Win64\ >nul 2>nul
copy *.txt BlackMagii_Win64\ >nul 2>nul

echo Creating ZIP archive...
powershell -Command "Compress-Archive -Path BlackMagii_Win64\* -DestinationPath BlackMagii_Win64_MinGW.zip -Force"
echo ✅ Package created: BlackMagii_Win64_MinGW.zip
pause
goto menu

REM ═══════════════════════════════════════
REM Build Functions
REM ═══════════════════════════════════════

:build_blackmagii_core
echo   📝 Compiling BlackMagii_Compiler.cpp...
g++ -std=c++17 -O2 -DWIN32 -D_WIN32 -c BlackMagii_Compiler.cpp -o obj\BlackMagii.o
if %errorlevel% neq 0 (
    echo   ❌ Compilation failed!
    exit /b 1
)
echo   🔗 Linking...
g++ -static -static-libgcc -static-libstdc++ -o bin\BlackMagii.exe obj\BlackMagii.o -lws2_32 -lwininet -lshlwapi
echo   ✅ BlackMagii.exe created!
exit /b 0

:build_enhanced_core
echo   📝 Compiling BlackMagii_Enhanced.cpp...
g++ -std=c++17 -O2 -DWIN32 -D_WIN32 -c BlackMagii_Enhanced.cpp -o obj\BlackMagii_Enhanced.o
if %errorlevel% neq 0 (
    echo   ❌ Compilation failed!
    exit /b 1
)
echo   🔗 Linking...
g++ -static -static-libgcc -static-libstdc++ -o bin\BlackMagii_Enhanced.exe obj\BlackMagii_Enhanced.o -lz -lws2_32 -lwininet -lshlwapi
echo   ✅ BlackMagii_Enhanced.exe created!
exit /b 0

:build_blackmamba_core
echo   📝 Compiling BlackMamba_IRC_Bot.cpp...
echo   Note: This requires libcurl. If compilation fails, install curl-devel
g++ -std=c++17 -O2 -DWIN32 -D_WIN32 -c BlackMamba_IRC_Bot.cpp -o obj\BlackMamba.o 2>nul
if %errorlevel% neq 0 (
    echo   ⚠️  Skipping BlackMamba (requires libcurl)
    exit /b 0
)
echo   🔗 Linking...
g++ -static -static-libgcc -static-libstdc++ -o bin\BlackMamba.exe obj\BlackMamba.o -lcurl -lws2_32
echo   ✅ BlackMamba.exe created!
exit /b 0

:build_mobile_core
echo   📝 Compiling MobileCompilerService.cpp...
g++ -std=c++17 -O2 -DWIN32 -D_WIN32 -c MobileCompilerService.cpp -o obj\MobileCompiler.o 2>nul
if %errorlevel% neq 0 (
    echo   ⚠️  Skipping Mobile Compiler (requires additional libs)
    exit /b 0
)
echo   🔗 Linking...
g++ -static -static-libgcc -static-libstdc++ -o bin\MobileCompiler.exe obj\MobileCompiler.o -lcurl -lws2_32
echo   ✅ MobileCompiler.exe created!
exit /b 0

:build_encryptor_core
echo   📝 Compiling VS2022_MenuEncryptor.cpp...
g++ -std=c++17 -O2 -DWIN32 -D_WIN32 -c VS2022_MenuEncryptor.cpp -o obj\VS2022_MenuEncryptor.o
if %errorlevel% neq 0 (
    echo   ❌ Compilation failed!
    exit /b 1
)
echo   🔗 Linking...
g++ -static -static-libgcc -static-libstdc++ -o bin\VS2022_MenuEncryptor.exe obj\VS2022_MenuEncryptor.o -lws2_32 -lcrypt32
echo   ✅ VS2022_MenuEncryptor.exe created!
exit /b 0

:download_dependencies
echo.
echo 📥 Downloading MinGW dependencies...
echo This feature is coming soon!
echo.
echo For now, please install dependencies manually:
echo.
echo MSYS2 users:
echo   pacman -S mingw-w64-x86_64-zlib
echo   pacman -S mingw-w64-x86_64-curl
echo.
pause
exit /b 0