@echo off
REM Star Master Toolkit Build Script for Windows
REM Enhanced RNG + Unified Security Tools Platform

setlocal enabledelayedexpansion

set "PROJECT_NAME=StarMasterToolkit"
set "BUILD_DIR=%~dp0build"
set "INSTALL_DIR=%~dp0dist"
set "CMAKE_ARGS=-DCMAKE_BUILD_TYPE=Release"

REM Colors (if supported)
set "GREEN=[92m"
set "YELLOW=[93m"
set "RED=[91m"
set "BLUE=[94m"
set "NC=[0m"

echo.
echo %BLUE%╔══════════════════════════════════════════════════════════════════╗%NC%
echo %BLUE%║                    STAR MASTER TOOLKIT BUILD                    ║%NC%
echo %BLUE%║                    Enhanced RNG + Unified Tools                 ║%NC%
echo %BLUE%╚══════════════════════════════════════════════════════════════════╝%NC%
echo.

REM Check for CMake
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo %RED%[ERROR]%NC% CMake not found in PATH
    echo Please install CMake from: https://cmake.org/download/
    echo Or install Visual Studio with CMake support
    pause
    exit /b 1
)

REM Check for Visual Studio or Build Tools
set "VS_FOUND=0"
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_FOUND=1"
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_FOUND=1"
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_FOUND=1"
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_FOUND=1"
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_FOUND=1"
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_FOUND=1"
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" (
            call "%%i\VC\Auxiliary\Build\vcvars64.bat"
            set "VS_FOUND=1"
        )
    )
)

if "%VS_FOUND%"=="0" (
    echo %YELLOW%[WARN]%NC% Visual Studio not found, trying with system compiler
)

echo %GREEN%[INFO]%NC% Setting up build environment...

REM Clean previous build
if exist "%BUILD_DIR%" (
    echo %GREEN%[INFO]%NC% Cleaning previous build...
    rmdir /s /q "%BUILD_DIR%"
)

REM Create build directories
mkdir "%BUILD_DIR%"
mkdir "%INSTALL_DIR%"

echo %GREEN%[INFO]%NC% Configuring build with CMake...
cd /d "%BUILD_DIR%"

REM Configure with CMake
cmake %CMAKE_ARGS% -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%" "%~dp0"
if %errorlevel% neq 0 (
    echo %RED%[ERROR]%NC% CMake configuration failed
    pause
    exit /b 1
)

echo %GREEN%[INFO]%NC% Building %PROJECT_NAME%...

REM Build the project
cmake --build . --config Release --parallel
if %errorlevel% neq 0 (
    echo %RED%[ERROR]%NC% Build failed
    pause
    exit /b 1
)

echo %GREEN%[INFO]%NC% Build completed successfully!

REM Check if executable was created
if exist "Release\%PROJECT_NAME%.exe" (
    echo %GREEN%[INFO]%NC% Executable created: Release\%PROJECT_NAME%.exe
) else if exist "%PROJECT_NAME%.exe" (
    echo %GREEN%[INFO]%NC% Executable created: %PROJECT_NAME%.exe
) else (
    echo %YELLOW%[WARN]%NC% Executable not found in expected location
)

echo.
echo %GREEN%Build Summary:%NC%
echo   Project: %PROJECT_NAME%
echo   Build Directory: %BUILD_DIR%
echo   Install Directory: %INSTALL_DIR%
echo.
echo %BLUE%Next Steps:%NC%
echo   1. Test the executable in the build directory
echo   2. Read README.md for usage instructions
echo   3. Check examples for implementation guides
echo.

REM Ask if user wants to run the executable
set /p "RUN_EXEC=Run the toolkit now? (y/N): "
if /i "%RUN_EXEC%"=="y" (
    if exist "Release\%PROJECT_NAME%.exe" (
        echo %GREEN%[INFO]%NC% Starting %PROJECT_NAME%...
        Release\%PROJECT_NAME%.exe
    ) else if exist "%PROJECT_NAME%.exe" (
        echo %GREEN%[INFO]%NC% Starting %PROJECT_NAME%...
        %PROJECT_NAME%.exe
    ) else (
        echo %RED%[ERROR]%NC% Executable not found
    )
)

pause