@echo off
echo ========================================================================================
echo BENIGN PACKER - BUILD SCRIPT FOR VISUAL STUDIO 2022
echo ========================================================================================
echo.

REM Check for Visual Studio 2022
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Visual Studio 2022 compiler (cl.exe) not found!
    echo Please run this script from "Developer Command Prompt for VS 2022"
    echo.
    echo To open Developer Command Prompt:
    echo 1. Press Win + R
    echo 2. Type: "cmd"
    echo 3. Press Enter
    echo 4. Run: "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
    echo 5. Navigate to this directory
    echo 6. Run this script again
    pause
    exit /b 1
)

echo Found Visual Studio 2022 compiler: cl.exe
echo.

REM Create output directories
if not exist "bin" mkdir bin
if not exist "obj" mkdir obj
if not exist "output" mkdir output

echo ========================================================================================
echo COMPILING COMPONENTS...
echo ========================================================================================

REM Compile IStubGenerator (interface)
echo Compiling IStubGenerator.h...
cl.exe /c /EHsc /std:c++17 /O2 /MT /DNDEBUG /I. IStubGenerator.h /Foobj\IStubGenerator.obj
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile IStubGenerator.h
    pause
    exit /b 1
)

REM Compile UniqueStub71Plugin
echo Compiling UniqueStub71Plugin...
cl.exe /c /EHsc /std:c++17 /O2 /MT /DNDEBUG /I. /DUNIQUE_STUB_71_EXPORTS UniqueStub71Plugin.cpp /Foobj\UniqueStub71Plugin.obj
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile UniqueStub71Plugin.cpp
    pause
    exit /b 1
)

REM Compile MASMAssemblerPlugin
echo Compiling MASMAssemblerPlugin...
cl.exe /c /EHsc /std:c++17 /O2 /MT /DNDEBUG /I. MASMAssemblerPlugin.cpp /Foobj\MASMAssemblerPlugin.obj
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile MASMAssemblerPlugin.cpp
    pause
    exit /b 1
)

REM Compile main BenignPacker application
echo Compiling BenignPacker main application...
cl.exe /c /EHsc /std:c++17 /O2 /MT /DNDEBUG /I. BenignPacker.cpp /Foobj\BenignPacker.obj
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile BenignPacker.cpp
    pause
    exit /b 1
)

echo ========================================================================================
echo LINKING EXECUTABLE...
echo ========================================================================================

REM Link the main executable
echo Linking BenignPacker.exe...
link.exe /OUT:bin\BenignPacker.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 ^
    obj\BenignPacker.obj ^
    obj\UniqueStub71Plugin.obj ^
    obj\MASMAssemblerPlugin.obj ^
    kernel32.lib user32.lib advapi32.lib shell32.lib psapi.lib wincrypt.lib wininet.lib
if %errorlevel% neq 0 (
    echo ERROR: Failed to link BenignPacker.exe
    pause
    exit /b 1
)

echo ========================================================================================
echo BUILD SUCCESSFUL!
echo ========================================================================================
echo.
echo Generated files:
echo   bin\BenignPacker.exe - Main application
echo.
echo Usage:
echo   bin\BenignPacker.exe <input_file> [output_file] [method]
echo.
echo Examples:
echo   bin\BenignPacker.exe payload.bin
echo   bin\BenignPacker.exe payload.bin output.exe advanced
echo   bin\BenignPacker.exe payload.bin stealth_output.exe stealth
echo.
echo Methods: default, advanced, mutex, stealth
echo.

REM Create a test payload for testing
echo Creating test payload...
echo Test payload data > test_payload.bin
echo.

echo ========================================================================================
echo TESTING THE APPLICATION...
echo ========================================================================================

if exist "test_payload.bin" (
    echo Testing with sample payload...
    bin\BenignPacker.exe test_payload.bin test_output.exe advanced
    if %errorlevel% equ 0 (
        echo.
        echo SUCCESS: Test completed successfully!
        echo Generated: test_output.exe
    ) else (
        echo.
        echo WARNING: Test failed, but build was successful.
        echo You can still use the application manually.
    )
) else (
    echo No test payload found. Build completed successfully.
)

echo.
echo ========================================================================================
echo BUILD COMPLETED!
echo ========================================================================================
echo.
echo Your BenignPacker is ready to use!
echo.
pause