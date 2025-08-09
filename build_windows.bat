@echo off
echo Building VS2022 GUI Benign Packer for Windows...
echo.

REM Try to find Visual Studio 2022 installation
set "VS_PATH="
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else (
    echo ERROR: Visual Studio 2022 not found!
    echo Please install Visual Studio 2022 with C++ development tools.
    pause
    exit /b 1
)

echo Found Visual Studio at: %VS_PATH%
echo Setting up build environment...
call "%VS_PATH%"

echo.
echo Compiling VS2022_GUI_Benign_Packer.cpp...
cl.exe /nologo /std:c++17 /EHsc /O2 /DNDEBUG /DUNICODE /D_UNICODE ^
    VS2022_GUI_Benign_Packer.cpp ^
    /Fe:VS2022_GUI_Benign_Packer.exe ^
    /link /SUBSYSTEM:WINDOWS ^
    ole32.lib crypt32.lib wininet.lib wintrust.lib imagehlp.lib ^
    comctl32.lib shell32.lib advapi32.lib user32.lib kernel32.lib gdi32.lib

if %ERRORLEVEL% equ 0 (
    echo.
    echo ======================================
    echo BUILD SUCCESSFUL!
    echo ======================================
    echo Output: VS2022_GUI_Benign_Packer.exe
    echo.
    echo The executable has been built and is ready to use.
    echo Double-click VS2022_GUI_Benign_Packer.exe to run it.
    echo.
) else (
    echo.
    echo ======================================
    echo BUILD FAILED!
    echo ======================================
    echo Please check the error messages above.
    echo Make sure you have Visual Studio 2022 with C++ tools installed.
    echo.
)

pause