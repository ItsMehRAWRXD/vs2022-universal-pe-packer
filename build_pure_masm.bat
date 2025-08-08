@echo off
echo ========================================================================================
echo MASM 2035 - TRULY PURE ASSEMBLY BUILD SCRIPT
echo No C++, No Hybrid Code, 100%% Native Microsoft Macro Assembler
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

REM Clean previous builds
echo Cleaning previous builds...
if exist "MASM_2035_TRULY_PURE.obj" del "MASM_2035_TRULY_PURE.obj"
if exist "MASM_2035_TRULY_PURE.exe" del "MASM_2035_TRULY_PURE.exe"
if exist "MASM_2035_TRULY_PURE.lst" del "MASM_2035_TRULY_PURE.lst"
if exist "MASM_2035_TRULY_PURE.ilk" del "MASM_2035_TRULY_PURE.ilk"
if exist "MASM_2035_TRULY_PURE.pdb" del "MASM_2035_TRULY_PURE.pdb"

echo ========================================================================================
echo ASSEMBLING: MASM_2035_TRULY_PURE.asm
echo ========================================================================================

REM Assemble with full error checking and listing generation
ml.exe /c /coff /Cp /W3 /WX /Zi /Zd /Fl /Fm /Fr MASM_2035_TRULY_PURE.asm

if errorlevel 1 (
    echo.
    echo ========================================================================================  
    echo ASSEMBLY FAILED!
    echo ========================================================================================
    echo Check the source code for syntax errors.
    echo Review the listing file: MASM_2035_TRULY_PURE.lst
    pause
    exit /b 1
)

echo.
echo ✅ Assembly successful! Object file created: MASM_2035_TRULY_PURE.obj
echo.

echo ========================================================================================
echo LINKING: Creating Windows executable
echo ========================================================================================

REM Link with Windows subsystem and debug information
link.exe /subsystem:windows /debug /debugtype:cv /machine:x86 /opt:ref /opt:icf MASM_2035_TRULY_PURE.obj

if errorlevel 1 (
    echo.
    echo ========================================================================================
    echo LINKING FAILED!
    echo ========================================================================================
    echo Check for missing libraries or unresolved symbols.
    pause
    exit /b 1
)

echo.
echo ========================================================================================
echo ✅ BUILD SUCCESSFUL! 
echo ========================================================================================
echo.
echo 📁 Generated Files:
echo    - MASM_2035_TRULY_PURE.exe     (Main executable)
echo    - MASM_2035_TRULY_PURE.obj     (Object file)
echo    - MASM_2035_TRULY_PURE.lst     (Assembly listing)
echo    - MASM_2035_TRULY_PURE.pdb     (Debug symbols)
echo.
echo 📊 MASM 2035 Features:
echo    ✅ 40+ Advanced Mutex Systems
echo    ✅ Company Profile Spoofing (Microsoft, Adobe, Google, NVIDIA, Intel)
echo    ✅ Anti-Analysis Detection (Debugger, VM, Timing)
echo    ✅ UAC Bypass Techniques (FodHelper)
echo    ✅ Process Injection Framework
echo    ✅ Polymorphic Code Generation
echo    ✅ Pure Assembly Implementation (701 lines)
echo.
echo 🚀 Usage:
echo    MASM_2035_TRULY_PURE.exe
echo.
echo 🎯 Target: Windows 10/11 (x86)
echo 💾 Size: ~%~z1 bytes (optimized)
echo 🔧 Built with: Microsoft Macro Assembler (MASM32)
echo.

REM Display file information
if exist "MASM_2035_TRULY_PURE.exe" (
    echo 📈 Executable Information:
    dir "MASM_2035_TRULY_PURE.exe" | find "MASM_2035_TRULY_PURE.exe"
    echo.
)

echo ========================================================================================
echo 🏆 MASM 2035 PURE ASSEMBLY BUILD COMPLETE!
echo Ready for deployment and testing.
echo ========================================================================================
pause