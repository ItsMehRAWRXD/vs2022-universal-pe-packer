@echo off
echo Building MASM 2035 Framework...
echo ================================

cd build/vs2022

echo Building Release configuration...
MSBuild MASM_2035.sln /p:Configuration=Release /p:Platform=x64 /m

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Build successful!
    echo Output: build/vs2022/x64/Release/
) else (
    echo.
    echo ❌ Build failed with error code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

pause
