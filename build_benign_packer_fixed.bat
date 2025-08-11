@echo off
echo Building BenignPacker with Plugin Framework...
echo ================================================

REM Set Visual Studio environment
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if errorlevel 1 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" 2>nul
    if errorlevel 1 (
        call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
        if errorlevel 1 (
            echo Error: Visual Studio 2022 not found!
            echo Please install Visual Studio 2022 with C++ build tools
            pause
            exit /b 1
        )
    )
)

echo Visual Studio environment loaded successfully
echo ================================================

REM Create output directory
if not exist "bin" mkdir bin
if not exist "obj" mkdir obj

echo Compiling BenignPacker.cpp...
cl.exe /std:c++17 /EHsc /O2 /MT ^
    /I"." ^
    /I"PluginFramework" ^
    /D_WIN32_WINNT=0x0601 ^
    /DWIN32_LEAN_AND_MEAN ^
    /DUNICODE ^
    /D_UNICODE ^
    /Fe:"bin\BenignPacker.exe" ^
    /Fo:"obj\\" ^
    BenignPacker.cpp ^
    UniqueStub71Plugin.cpp ^
    MASMAssemblerPlugin.cpp ^
    /link ^
    kernel32.lib ^
    user32.lib ^
    advapi32.lib ^
    shell32.lib ^
    crypt32.lib ^
    wininet.lib ^
    psapi.lib ^
    /OUT:"bin\BenignPacker.exe"

if errorlevel 1 (
    echo Compilation failed!
    echo ================================================
    echo Common issues:
    echo 1. Make sure Visual Studio 2022 is installed with C++ build tools
    echo 2. Check that all source files exist in the current directory
    echo 3. Verify that PluginFramework/IPlugin.h exists
    echo ================================================
    pause
    exit /b 1
)

echo ================================================
echo Compilation successful!
echo Output: bin\BenignPacker.exe
echo ================================================

REM Test the executable
if exist "bin\BenignPacker.exe" (
    echo Testing BenignPacker...
    echo Creating test payload...
    echo Test payload data > test_payload.bin
    
    echo Running BenignPacker...
    bin\BenignPacker.exe test_payload.bin test_output.exe advanced
    
    if exist "test_output.exe" (
        echo SUCCESS: Test output file created!
        echo File size: 
        dir test_output.exe | find "test_output.exe"
    ) else (
        echo WARNING: Test output file not created
    )
    
    echo Cleaning up test files...
    if exist "test_payload.bin" del test_payload.bin
    if exist "test_output.exe" del test_output.exe
)

echo ================================================
echo Build completed successfully!
echo You can now use: bin\BenignPacker.exe <input_file> [output_file] [method]
echo ================================================
pause