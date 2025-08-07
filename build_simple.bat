@echo off
echo === SIMPLE WORKING PACKER BUILD ===
echo.

echo [INFO] Compiling SimplePacker...
cl.exe /std:c++17 /O2 /MT /DWIN32_LEAN_AND_MEAN /EHsc SIMPLE_WORKING_PACKER.cpp /link /SUBSYSTEM:CONSOLE /MACHINE:x64 kernel32.lib user32.lib /OUT:SimplePacker.exe

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] SimplePacker.exe created successfully!
    echo.
    echo [INFO] Usage examples:
    echo SimplePacker.exe payload.bin output.exe exe
    echo SimplePacker.exe payload.bin output.cpp cpp
    echo.
    echo [INFO] Test with a sample payload:
    echo echo Test payload > test_payload.bin
    echo SimplePacker.exe test_payload.bin test_output.exe exe
) else (
    echo [ERROR] Compilation failed!
)

pause