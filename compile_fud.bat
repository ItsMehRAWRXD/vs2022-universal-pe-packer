@echo off
title VS2022 FUD Manual Compilation Tool
color 0A

echo.
echo ================================================================
echo             VS2022 FUD PACKER - MANUAL COMPILATION
echo ================================================================
echo.

set SOURCE_FILE=%1
if "%SOURCE_FILE%"=="" (
    echo Usage: compile_fud.bat [YourSourceFile.cpp] [OutputName.exe]
    echo.
    echo Example: compile_fud.bat VS2022_FUD_12345.cpp MyFUD.exe
    echo.
    echo If no output name specified, will use source filename
    echo.
    pause
    exit /b 1
)

REM Check if source file exists
if not exist "%SOURCE_FILE%" (
    echo ERROR: Source file "%SOURCE_FILE%" not found!
    echo.
    echo Please ensure the .cpp file is in the current directory
    pause
    exit /b 1
)

REM Determine output filename
set OUTPUT_FILE=%2
if "%OUTPUT_FILE%"=="" (
    set OUTPUT_FILE=%~n1.exe
)

echo Source File: %SOURCE_FILE%
echo Output File: %OUTPUT_FILE%
echo.
echo Starting compilation process...
echo.

REM Method 1: Try VS2022 Developer Environment (cl.exe in PATH)
echo [1/7] Trying VS2022 Developer Command Prompt environment...
cl.exe /nologo /O1 /MT /TC /bigobj "%SOURCE_FILE%" /Fe:"%OUTPUT_FILE%" /link /SUBSYSTEM:WINDOWS /LARGEADDRESSAWARE /DYNAMICBASE /NXCOMPAT user32.lib kernel32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib >compile_log.txt 2>&1

if %ERRORLEVEL%==0 (
    goto SUCCESS
)

REM Method 2: Try to find VS2022 Community
echo [2/7] Trying VS2022 Community installation...
for /f "tokens=*" %%i in ('dir "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC" /b /o:d 2^>nul') do (
    set MSVC_VER=%%i
    goto FOUND_COMMUNITY
)
goto TRY_ENTERPRISE

:FOUND_COMMUNITY
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\%MSVC_VER%\bin\Hostx64\x64\cl.exe" /nologo /O1 /MT /TC /bigobj "%SOURCE_FILE%" /Fe:"%OUTPUT_FILE%" /link /SUBSYSTEM:WINDOWS /LARGEADDRESSAWARE /DYNAMICBASE /NXCOMPAT user32.lib kernel32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib >compile_log.txt 2>&1

if %ERRORLEVEL%==0 (
    goto SUCCESS
)

:TRY_ENTERPRISE
REM Method 3: Try VS2022 Enterprise
echo [3/7] Trying VS2022 Enterprise installation...
for /f "tokens=*" %%i in ('dir "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC" /b /o:d 2^>nul') do (
    set MSVC_VER=%%i
    goto FOUND_ENTERPRISE
)
goto TRY_PROFESSIONAL

:FOUND_ENTERPRISE
"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\%MSVC_VER%\bin\Hostx64\x64\cl.exe" /nologo /O1 /MT /TC /bigobj "%SOURCE_FILE%" /Fe:"%OUTPUT_FILE%" /link /SUBSYSTEM:WINDOWS /LARGEADDRESSAWARE /DYNAMICBASE /NXCOMPAT user32.lib kernel32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib >compile_log.txt 2>&1

if %ERRORLEVEL%==0 (
    goto SUCCESS
)

:TRY_PROFESSIONAL
REM Method 4: Try VS2022 Professional
echo [4/7] Trying VS2022 Professional installation...
for /f "tokens=*" %%i in ('dir "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC" /b /o:d 2^>nul') do (
    set MSVC_VER=%%i
    goto FOUND_PROFESSIONAL
)
goto TRY_VSWHERE

:FOUND_PROFESSIONAL
"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\%MSVC_VER%\bin\Hostx64\x64\cl.exe" /nologo /O1 /MT /TC /bigobj "%SOURCE_FILE%" /Fe:"%OUTPUT_FILE%" /link /SUBSYSTEM:WINDOWS /LARGEADDRESSAWARE /DYNAMICBASE /NXCOMPAT user32.lib kernel32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib >compile_log.txt 2>&1

if %ERRORLEVEL%==0 (
    goto SUCCESS
)

:TRY_VSWHERE
REM Method 5: Try using vswhere
echo [5/7] Trying vswhere to locate VS2022...
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -version [17.0,18.0) -property installationPath 2^>nul`) do (
        for /f "tokens=*" %%j in ('dir "%%i\VC\Tools\MSVC" /b /o:d 2^>nul') do (
            "%%i\VC\Tools\MSVC\%%j\bin\Hostx64\x64\cl.exe" /nologo /O1 /MT /TC /bigobj "%SOURCE_FILE%" /Fe:"%OUTPUT_FILE%" /link /SUBSYSTEM:WINDOWS /LARGEADDRESSAWARE /DYNAMICBASE /NXCOMPAT user32.lib kernel32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib >compile_log.txt 2>&1
            if !ERRORLEVEL!==0 (
                goto SUCCESS
            )
        )
    )
)

REM Method 6: Try MinGW
echo [6/7] Trying MinGW compiler...
gcc -std=c99 -O2 -static -mwindows "%SOURCE_FILE%" -o "%OUTPUT_FILE%" -luser32 -lkernel32 -lgdi32 -ladvapi32 -lshell32 -lole32 >compile_log.txt 2>&1

if %ERRORLEVEL%==0 (
    goto SUCCESS
)

REM Method 7: Try TinyC
echo [7/7] Trying TinyC compiler...
tcc -o "%OUTPUT_FILE%" "%SOURCE_FILE%" -luser32 -lkernel32 -lgdi32 -ladvapi32 -lshell32 >compile_log.txt 2>&1

if %ERRORLEVEL%==0 (
    goto SUCCESS
)

REM All methods failed
goto FAILED

:SUCCESS
echo.
echo ================================================================
echo                    COMPILATION SUCCESSFUL!
echo ================================================================
echo.
echo Output File: %OUTPUT_FILE%

if exist "%OUTPUT_FILE%" (
    echo File Size: 
    dir "%OUTPUT_FILE%" | find "%OUTPUT_FILE%"
    echo.
    
    REM Check file size
    for %%A in ("%OUTPUT_FILE%") do set file_size=%%~zA
    if %file_size% GTR 30720 (
        echo ✓ EXCELLENT: File size ^>30KB - indicates proper payload embedding
        echo ✓ READY FOR VIRUSTOTAL: This executable is production ready
    ) else if %file_size% GTR 10240 (
        echo ⚠ WARNING: File size is smaller than expected
        echo   This may indicate missing payload or benign mode
    ) else (
        echo ⚠ SMALL FILE: File size ^<10KB - likely benign stub only
    )
    
    echo.
    echo Features included in compiled executable:
    echo • Polymorphic code obfuscation
    echo • Anti-debugging protection  
    echo • Sandbox evasion techniques
    echo • Runtime payload extraction
    echo • Enterprise-grade encryption
    echo • Dynamic execution protection
    echo.
    echo The executable is ready for testing and VirusTotal upload!
) else (
    echo ERROR: Output file was not created despite successful compilation!
)

goto END

:FAILED
echo.
echo ================================================================
echo                   COMPILATION FAILED!
echo ================================================================
echo.
echo All compilation methods failed. Please try one of these solutions:
echo.
echo 1. OPEN DEVELOPER COMMAND PROMPT:
echo    Start Menu ^> "Developer Command Prompt for VS 2022"
echo    Then run: compile_fud.bat "%SOURCE_FILE%"
echo.
echo 2. INSTALL MISSING COMPONENTS:
echo    • Visual Studio 2022 with C++ build tools
echo    • Windows 10/11 SDK
echo    • MSVC v143 compiler toolset
echo.
echo 3. USE VISUAL STUDIO IDE:
echo    • Create new Empty Project
echo    • Add your .cpp file to project
echo    • Set Configuration to Release, Platform to x64
echo    • Set Compile As: "Compile as C Code (/TC)"
echo    • Set Runtime Library: "Multi-threaded (/MT)"
echo    • Build Solution
echo.
echo 4. CHECK COMPILATION LOG:
if exist compile_log.txt (
    echo    See compile_log.txt for detailed error messages
) else (
    echo    No compilation log generated
)
echo.

:END
echo.
if exist compile_log.txt (
    echo Compilation log saved as: compile_log.txt
    echo.
)
echo Press any key to exit...
pause >nul