@echo off
setlocal enabledelayedexpansion
echo ========================================
echo   Portable Compiler Setup for FUD Packer
echo ========================================
echo.

echo [1/5] Creating portable compiler directory...
if not exist "portable_compiler" mkdir portable_compiler
cd portable_compiler

echo [2/5] Downloading MinGW-w64 portable...
echo Downloading MinGW-w64 portable compiler...

REM Download MinGW-w64 portable
powershell -Command "try { 
    $url = 'https://github.com/niXman/mingw-builds-binaries/releases/download/13.2.0-rt_v11-rev1/winlibs-x86_64-posix-seh-gcc-13.2.0-mingw-w64-11.0.1-r1.zip'
    $output = 'mingw64.zip'
    Write-Host 'Downloading MinGW-w64...'
    Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing
    Write-Host 'Download completed!'
} catch { 
    Write-Host 'Download failed, trying alternative source...'
    $url = 'https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-posix/seh/x86_64-8.1.0-release-posix-seh-rt_v6-rev0.7z/download'
    $output = 'mingw64.7z'
    Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing
}"

if exist "mingw64.zip" (
    echo [3/5] Extracting MinGW-w64...
    powershell -Command "try { Expand-Archive -Path 'mingw64.zip' -DestinationPath '.' -Force } catch { exit 1 }"
    del mingw64.zip
) else if exist "mingw64.7z" (
    echo [3/5] Extracting MinGW-w64 (7z format)...
    powershell -Command "try { & 'C:\Program Files\7-Zip\7z.exe' x mingw64.7z -y } catch { exit 1 }"
    del mingw64.7z
)

echo [4/5] Setting up compiler environment...

REM Create a batch file to set up the environment
echo @echo off > setup_env.bat
echo set PATH=%%~dp0mingw64\bin;%%PATH%% >> setup_env.bat
echo set CC=gcc >> setup_env.bat
echo set CXX=g++ >> setup_env.bat
echo echo MinGW-w64 environment set up successfully! >> setup_env.bat
echo echo You can now compile with: g++ -O2 source.cpp -o output.exe >> setup_env.bat

REM Create a compilation script
echo @echo off > compile.bat
echo set PATH=%%~dp0mingw64\bin;%%PATH%% >> compile.bat
echo if "%%1"=="" ( >> compile.bat
echo     echo Usage: compile.bat ^<source.cpp^> [output.exe] >> compile.bat
echo     exit /b 1 >> compile.bat
echo ) >> compile_bat
echo if "%%2"=="" set OUTPUT=%%~n1.exe >> compile.bat
echo if not "%%2"=="" set OUTPUT=%%2 >> compile.bat
echo g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ -mwindows "%%1" -o "%%OUTPUT%%" -luser32 -lkernel32 -lgdi32 -ladvapi32 -lshell32 -lole32 -lcomctl32 -lwininet -lcrypt32 -lwintrust -limagehlp >> compile.bat
echo if %%ERRORLEVEL%% equ 0 ( >> compile.bat
echo     echo Compilation successful: %%OUTPUT%% >> compile.bat
echo ) else ( >> compile.bat
echo     echo Compilation failed! >> compile.bat
echo ) >> compile.bat

echo [5/5] Testing compiler installation...

REM Test the compiler
if exist "mingw64\bin\g++.exe" (
    echo Testing g++ compiler...
    mingw64\bin\g++ --version > compiler_test.txt 2>&1
    if %ERRORLEVEL% equ 0 (
        echo.
        echo ======================================
        echo PORTABLE COMPILER SETUP SUCCESSFUL!
        echo ======================================
        echo.
        echo The portable compiler is now ready to use.
        echo.
        echo To compile a source file:
        echo   compile.bat source.cpp output.exe
        echo.
        echo To set up environment for other tools:
        echo   setup_env.bat
        echo.
        echo Compiler location: mingw64\bin\g++.exe
        echo.
    ) else (
        echo Compiler test failed!
        echo Check compiler_test.txt for details.
    )
) else (
    echo ERROR: Compiler not found after extraction!
    echo Please check the download and extraction process.
)

cd ..
echo.
echo Setup complete! The portable compiler is in the 'portable_compiler' directory.
pause