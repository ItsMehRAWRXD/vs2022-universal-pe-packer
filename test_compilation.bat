@echo off
echo Testing compilation command manually...
echo.

REM Set up VS environment
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

REM Test if cl.exe is available
echo Testing cl.exe availability...
where cl.exe
if %errorlevel% neq 0 (
    echo ERROR: cl.exe not found in PATH
    pause
    exit /b 1
)

echo.
echo VS Environment set up successfully!
echo.

REM Try to compile a simple test file first
echo #include ^<iostream^> > test_simple.cpp
echo int main() { std::cout ^<^< "Hello World"; return 0; } >> test_simple.cpp

echo Testing simple compilation...
cl.exe /nologo /O2 /EHsc test_simple.cpp /Fe:test_simple.exe
if %errorlevel% neq 0 (
    echo ERROR: Simple compilation failed
    pause
    exit /b 1
)

echo Simple compilation SUCCESS!
echo.

REM Now test with Windows headers
echo #include ^<windows.h^> > test_windows.cpp
echo #include ^<iostream^> >> test_windows.cpp  
echo int main() { >> test_windows.cpp
echo     MessageBoxA(NULL, "Test", "Test", MB_OK); >> test_windows.cpp
echo     return 0; >> test_windows.cpp
echo } >> test_windows.cpp

echo Testing Windows headers compilation...
cl.exe /nologo /O2 /EHsc /DNDEBUG /MD test_windows.cpp /Fe:test_windows.exe /link /MACHINE:X64 /SUBSYSTEM:CONSOLE user32.lib kernel32.lib
if %errorlevel% neq 0 (
    echo ERROR: Windows headers compilation failed
    pause
    exit /b 1
)

echo Windows compilation SUCCESS!
echo.

REM Now test the actual generated file if it exists
if exist temp_5hJRvyb9.cpp (
    echo Testing actual generated file...
    cl.exe /nologo /O2 /EHsc /DNDEBUG /MD temp_5hJRvyb9.cpp /Fe:test_generated.exe /link /MACHINE:X64 /SUBSYSTEM:CONSOLE user32.lib kernel32.lib advapi32.lib shell32.lib ole32.lib
    if %errorlevel% neq 0 (
        echo ERROR: Generated file compilation failed - check temp_5hJRvyb9.cpp for issues
    ) else (
        echo Generated file compilation SUCCESS!
    )
) else (
    echo temp_5hJRvyb9.cpp not found - will need to generate it first
)

echo.
echo All tests completed!
pause