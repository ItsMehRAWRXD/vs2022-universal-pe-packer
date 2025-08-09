@echo off
echo Testing Ultimate FUD Packer compilation...
echo.

echo Attempting Visual Studio compilation...
cl.exe /nologo /W3 /EHsc /D_CRT_SECURE_NO_WARNINGS UltimateFUDPacker_AutoCompile.cpp /Fe:UltimateFUDPacker.exe /link user32.lib gdi32.lib comctl32.lib comdlg32.lib

if %ERRORLEVEL% == 0 (
    echo SUCCESS: Visual Studio compilation completed!
    echo Generated: UltimateFUDPacker.exe
) else (
    echo Visual Studio compilation failed, trying MinGW...
    echo.
    
    gcc -std=c99 -Wall -O2 -mwindows UltimateFUDPacker_AutoCompile.cpp -o UltimateFUDPacker.exe -luser32 -lgdi32 -lcomctl32 -lcomdlg32
    
    if %ERRORLEVEL% == 0 (
        echo SUCCESS: MinGW compilation completed!
        echo Generated: UltimateFUDPacker.exe
    ) else (
        echo ERROR: Both compilers failed!
        echo Please check the source code for syntax errors.
    )
)

echo.
echo Compilation test complete.
pause