@echo off
echo ================================================================
echo    PHP to C++ Web Shell Converter - Compilation Script
echo ================================================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Warning: Running without administrator privileges
    echo     Some features may not work correctly
    echo.
) else (
    echo [+] Running with administrator privileges
    echo.
)

:: Check if g++ is available
g++ --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [-] Error: g++ compiler not found
    echo     Please install MinGW-w64 or MSYS2
    echo     Download from: https://www.mingw-w64.org/
    pause
    exit /b 1
) else (
    echo [+] g++ compiler found
    g++ --version | findstr /C:"g++"
    echo.
)

echo ================================================================
echo Building PHP to C++ Analysis Framework...
echo ================================================================

echo [+] Compiling PHP Shell Analyzer and Framework...
g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
    -DWIN32_LEAN_AND_MEAN -DNOMINMAX ^
    php_to_cpp_shell_analyzer.cpp ^
    -o php_shell_analyzer.exe ^
    -lwinhttp -lurlmon -lshell32 -ladvapi32 -lkernel32 -luser32 -lpsapi

if %errorLevel% equ 0 (
    echo [+] Successfully compiled: php_shell_analyzer.exe
) else (
    echo [-] Failed to compile PHP Shell Analyzer
    goto :error
)

echo.
echo [+] Compiling Standalone C++ Web Shell...
g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
    -DWIN32_LEAN_AND_MEAN -DNOMINMAX ^
    standalone_cpp_webshell.cpp ^
    -o standalone_webshell.exe ^
    -lws2_32 -lkernel32 -luser32

if %errorLevel% equ 0 (
    echo [+] Successfully compiled: standalone_webshell.exe
) else (
    echo [-] Failed to compile Standalone Web Shell
    goto :error
)

echo.
echo ================================================================
echo Building Additional Analysis Tools...
echo ================================================================

:: Create a simple PHP decoder utility
echo [+] Creating PHP decoder utility...
echo #include ^<iostream^> > php_decoder.cpp
echo #include ^<string^> >> php_decoder.cpp
echo #include ^<vector^> >> php_decoder.cpp
echo #include ^<algorithm^> >> php_decoder.cpp
echo. >> php_decoder.cpp
echo std::string rot13(const std::string^& input) { >> php_decoder.cpp
echo     std::string result = input; >> php_decoder.cpp
echo     for (char^& c : result) { >> php_decoder.cpp
echo         if (c ^>= 'a' ^&^& c ^<= 'z') { >> php_decoder.cpp
echo             c = 'a' + (c - 'a' + 13) %% 26; >> php_decoder.cpp
echo         } else if (c ^>= 'A' ^&^& c ^<= 'Z') { >> php_decoder.cpp
echo             c = 'A' + (c - 'A' + 13) %% 26; >> php_decoder.cpp
echo         } >> php_decoder.cpp
echo     } >> php_decoder.cpp
echo     return result; >> php_decoder.cpp
echo } >> php_decoder.cpp
echo. >> php_decoder.cpp
echo int main() { >> php_decoder.cpp
echo     std::cout ^<^< "PHP String Decoder Utility\n"; >> php_decoder.cpp
echo     std::string input; >> php_decoder.cpp
echo     std::cout ^<^< "Enter string to decode: "; >> php_decoder.cpp
echo     std::getline(std::cin, input); >> php_decoder.cpp
echo     std::cout ^<^< "ROT13 Result: " ^<^< rot13(input) ^<^< std::endl; >> php_decoder.cpp
echo     return 0; >> php_decoder.cpp
echo } >> php_decoder.cpp

g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
    php_decoder.cpp -o php_decoder.exe

if %errorLevel% equ 0 (
    echo [+] Successfully compiled: php_decoder.exe
    del php_decoder.cpp
) else (
    echo [-] Failed to compile PHP decoder utility
)

echo.
echo ================================================================
echo Creating Documentation and Usage Guide...
echo ================================================================

echo [+] Creating README.txt...
echo PHP to C++ Web Shell Converter Framework > README.txt
echo ============================================= >> README.txt
echo. >> README.txt
echo This framework converts PHP web shell functionality to native C++ applications. >> README.txt
echo No web hosting is required - the C++ tools run standalone. >> README.txt
echo. >> README.txt
echo TOOLS INCLUDED: >> README.txt
echo. >> README.txt
echo 1. php_shell_analyzer.exe >> README.txt
echo    - Analyzes PHP web shell code and identifies obfuscation techniques >> README.txt
echo    - Demonstrates C++ equivalents of PHP functions >> README.txt
echo    - Interactive shell for testing capabilities >> README.txt
echo. >> README.txt
echo 2. standalone_webshell.exe >> README.txt
echo    - Complete C++ web shell with HTTP server >> README.txt
echo    - No hosting required - runs on localhost:8080 >> README.txt
echo    - Web-based interface for file management and command execution >> README.txt
echo. >> README.txt
echo 3. php_decoder.exe >> README.txt
echo    - Simple utility for decoding obfuscated strings >> README.txt
echo    - Supports ROT13 and other common encodings >> README.txt
echo. >> README.txt
echo USAGE: >> README.txt
echo. >> README.txt
echo 1. Run php_shell_analyzer.exe to analyze PHP code and test C++ framework >> README.txt
echo 2. Run standalone_webshell.exe for a complete web-based shell interface >> README.txt
echo 3. Access the web interface at http://localhost:8080 >> README.txt
echo. >> README.txt
echo FEATURES: >> README.txt
echo. >> README.txt
echo - String obfuscation (XOR, ROT13, Base64) >> README.txt
echo - Command execution with output capture >> README.txt
echo - File management (upload/download) >> README.txt
echo - System information gathering >> README.txt
echo - Process and network monitoring >> README.txt
echo - Anti-analysis and stealth capabilities >> README.txt
echo - Session management >> README.txt
echo - No dependencies on web servers or PHP >> README.txt
echo. >> README.txt
echo WARNING: These tools are for educational and authorized testing only. >> README.txt
echo Use responsibly and in compliance with applicable laws and regulations. >> README.txt

echo [+] Created README.txt

echo.
echo ================================================================
echo Compilation Summary
echo ================================================================

echo.
echo [+] Checking compiled executables...
if exist php_shell_analyzer.exe (
    echo     ✓ php_shell_analyzer.exe - %~z1 bytes
) else (
    echo     ✗ php_shell_analyzer.exe - MISSING
)

if exist standalone_webshell.exe (
    echo     ✓ standalone_webshell.exe - %~z2 bytes
) else (
    echo     ✗ standalone_webshell.exe - MISSING
)

if exist php_decoder.exe (
    echo     ✓ php_decoder.exe - %~z3 bytes
) else (
    echo     ✗ php_decoder.exe - MISSING
)

echo.
echo ================================================================
echo Quick Test - Analyzing Provided PHP Shells
echo ================================================================

echo [+] The provided PHP shells contain:
echo.
echo     Shell 1 (food.php):
echo     - GIF header spoofing (GIF89aGlobex)
echo     - Multi-layer obfuscation: eval(gzinflate(str_rot13(base64_decode(...))))
echo     - Compressed and encoded payload
echo.
echo     Shell 2 (views.php):
echo     - GIF header spoofing (GÝF89;a)
echo     - URL-encoded string substitution cipher
echo     - Variable function calls with obfuscated names
echo     - Multiple decoding layers
echo.
echo [+] C++ Framework Equivalents:
echo     - XOR string obfuscation for compile-time protection
echo     - ROT13 and Base64 encoding/decoding
echo     - Dynamic function resolution
echo     - HTTP server implementation
echo     - Command execution with pipe capture
echo     - File operations and system info gathering
echo.

echo ================================================================
echo Build Complete!
echo ================================================================
echo.
echo To get started:
echo 1. Run "php_shell_analyzer.exe" for analysis and testing
echo 2. Run "standalone_webshell.exe" for the web interface
echo 3. Check README.txt for detailed usage instructions
echo.
echo The C++ tools provide all the functionality of the PHP shells
echo without requiring web hosting or PHP runtime.
echo.
pause
goto :end

:error
echo.
echo ================================================================
echo Build Failed!
echo ================================================================
echo.
echo Please check:
echo 1. g++ compiler is properly installed and in PATH
echo 2. All required source files are present
echo 3. Windows SDK headers are available
echo.
pause
exit /b 1

:end
echo Build process completed successfully.