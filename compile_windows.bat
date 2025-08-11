@echo off
echo ======================================================================
echo Enhanced Master Toolkit 2025 - Windows Compilation Script
echo ======================================================================

REM Check if g++ is available
where g++ >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: g++ not found. Please install MinGW-w64 or similar.
    echo Download from: https://www.mingw-w64.org/downloads/
    pause
    exit /b 1
)

echo.
echo Compiling Enhanced Master Toolkit (Windows Version)...
g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ enhanced_master_toolkit_windows.cpp -o enhanced_master_toolkit.exe -ladvapi32 -lkernel32 -luser32 -lpsapi

if %errorlevel% equ 0 (
    echo ✅ Enhanced Master Toolkit compiled successfully!
    echo    Output: enhanced_master_toolkit.exe
) else (
    echo ❌ Compilation failed!
    pause
    exit /b 1
)

echo.
echo Compiling Advanced Fileless Demo (Windows Version)...
g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ advanced_fileless_demo_windows.cpp -o advanced_fileless_demo.exe -ladvapi32 -lkernel32 -luser32

if %errorlevel% equ 0 (
    echo ✅ Advanced Fileless Demo compiled successfully!
    echo    Output: advanced_fileless_demo.exe
) else (
    echo ❌ Compilation failed!
    pause
    exit /b 1
)

echo.
echo ======================================================================
echo Compilation completed! 
echo.
echo Available executables:
echo   - enhanced_master_toolkit.exe     (Full toolkit with GUI)
echo   - advanced_fileless_demo.exe      (Standalone demo)
echo.
echo To run: ./enhanced_master_toolkit.exe
echo ======================================================================
pause