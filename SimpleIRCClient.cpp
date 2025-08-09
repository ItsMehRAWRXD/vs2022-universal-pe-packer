#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <richedit.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <random>
#include <filesystem>
#include <fstream>
#include <urlmon.h>
#include <shellapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shell32.lib")

// Window controls IDs
#define IDC_SERVER_EDIT     1001
#define IDC_PORT_EDIT       1002
#define IDC_NICK_EDIT       1003
#define IDC_CHANNEL_EDIT    1004
#define IDC_CONNECT_BTN     1005
#define IDC_DISCONNECT_BTN  1006
#define IDC_MESSAGE_EDIT    1007
#define IDC_SEND_BTN        1008
#define IDC_CHAT_DISPLAY    1009
#define IDC_USERLIST        1010
#define IDC_DOWNLOAD_BTN    1011
#define IDC_URL_EDIT        1012

class SimpleIRCClient {
private:
    HWND hMainWindow;
    HWND hServerEdit, hPortEdit, hNickEdit, hChannelEdit;
    HWND hConnectBtn, hDisconnectBtn;
    HWND hMessageEdit, hSendBtn;
    HWND hChatDisplay, hUserList;
    HWND hDownloadBtn, hUrlEdit;
    
    SOCKET ircSocket;
    bool isConnected;
    std::thread receiveThread;
    std::mutex displayMutex;
    
    std::string serverAddress;
    int serverPort;
    std::string nickname;
    std::string currentChannel;

public:
    SimpleIRCClient() : ircSocket(INVALID_SOCKET), isConnected(false) {
        WSAData wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }
    
    ~SimpleIRCClient() {
        disconnect();
        WSACleanup();
    }
    
    bool createMainWindow(HINSTANCE hInstance) {
        // Register window class
        WNDCLASS wc = {};
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.lpszClassName = L"SimpleIRCClient";
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        
        if (!RegisterClass(&wc)) return false;
        
        // Create main window
        hMainWindow = CreateWindowEx(
            0,
            L"SimpleIRCClient",
            L"Simple IRC Client with Random Nicknames & Download",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 800, 650,
            NULL, NULL, hInstance, this
        );
        
        if (!hMainWindow) return false;
        
        createControls();
        ShowWindow(hMainWindow, SW_SHOW);
        UpdateWindow(hMainWindow);
        
        return true;
    }
    
    void createControls() {
        // Load RichEdit library
        LoadLibrary(L"riched20.dll");
        
        int y = 10;
        
        // Server settings
        CreateWindow(L"STATIC", L"Server:", WS_VISIBLE | WS_CHILD,
            10, y, 60, 20, hMainWindow, NULL, NULL, NULL);
        hServerEdit = CreateWindow(L"EDIT", L"irc.libera.chat", 
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            75, y, 150, 20, hMainWindow, (HMENU)IDC_SERVER_EDIT, NULL, NULL);
        
        CreateWindow(L"STATIC", L"Port:", WS_VISIBLE | WS_CHILD,
            240, y, 40, 20, hMainWindow, NULL, NULL, NULL);
        hPortEdit = CreateWindow(L"EDIT", L"6667", 
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            285, y, 60, 20, hMainWindow, (HMENU)IDC_PORT_EDIT, NULL, NULL);
        
        y += 30;
        
        // Nickname (with random generation)
        CreateWindow(L"STATIC", L"Nickname:", WS_VISIBLE | WS_CHILD,
            10, y, 60, 20, hMainWindow, NULL, NULL, NULL);
        
        std::string randomNick = generateRandomNickname();
        std::wstring wRandomNick = stringToWstring(randomNick);
        hNickEdit = CreateWindow(L"EDIT", wRandomNick.c_str(), 
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            75, y, 100, 20, hMainWindow, (HMENU)IDC_NICK_EDIT, NULL, NULL);
        
        // Channel
        CreateWindow(L"STATIC", L"Channel:", WS_VISIBLE | WS_CHILD,
            190, y, 60, 20, hMainWindow, NULL, NULL, NULL);
        hChannelEdit = CreateWindow(L"EDIT", L"#test", 
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            255, y, 100, 20, hMainWindow, (HMENU)IDC_CHANNEL_EDIT, NULL, NULL);
        
        y += 30;
        
        // Connect/Disconnect buttons
        hConnectBtn = CreateWindow(L"BUTTON", L"Connect", 
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            10, y, 80, 25, hMainWindow, (HMENU)IDC_CONNECT_BTN, NULL, NULL);
        
        hDisconnectBtn = CreateWindow(L"BUTTON", L"Disconnect", 
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            100, y, 80, 25, hMainWindow, (HMENU)IDC_DISCONNECT_BTN, NULL, NULL);
        EnableWindow(hDisconnectBtn, FALSE);
        
        y += 35;
        
        // Chat display (RichEdit)
        hChatDisplay = CreateWindow(RICHEDIT_CLASS, L"",
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
            10, y, 550, 350, hMainWindow, (HMENU)IDC_CHAT_DISPLAY, NULL, NULL);
        
        // User list
        hUserList = CreateWindow(L"LISTBOX", L"",
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL,
            570, y, 200, 350, hMainWindow, (HMENU)IDC_USERLIST, NULL, NULL);
        
        y += 360;
        
        // Message input
        CreateWindow(L"STATIC", L"Message:", WS_VISIBLE | WS_CHILD,
            10, y, 60, 20, hMainWindow, NULL, NULL, NULL);
        
        hMessageEdit = CreateWindow(L"EDIT", L"", 
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            75, y, 400, 20, hMainWindow, (HMENU)IDC_MESSAGE_EDIT, NULL, NULL);
        
        hSendBtn = CreateWindow(L"BUTTON", L"Send", 
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            485, y, 60, 25, hMainWindow, (HMENU)IDC_SEND_BTN, NULL, NULL);
        EnableWindow(hSendBtn, FALSE);
        
        y += 30;
        
        // Download functionality
        CreateWindow(L"STATIC", L"Download URL:", WS_VISIBLE | WS_CHILD,
            10, y, 80, 20, hMainWindow, NULL, NULL, NULL);
        
        hUrlEdit = CreateWindow(L"EDIT", L"", 
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            95, y, 350, 20, hMainWindow, (HMENU)IDC_URL_EDIT, NULL, NULL);
        
        hDownloadBtn = CreateWindow(L"BUTTON", L"Download & Install", 
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            455, y, 120, 25, hMainWindow, (HMENU)IDC_DOWNLOAD_BTN, NULL, NULL);
    }
    
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        SimpleIRCClient* client = nullptr;
        
        if (uMsg == WM_NCCREATE) {
            CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
            client = (SimpleIRCClient*)cs->lpCreateParams;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)client);
        } else {
            client = (SimpleIRCClient*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
        }
        
        if (client) {
            return client->handleMessage(hwnd, uMsg, wParam, lParam);
        }
        
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    
    LRESULT handleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        switch (uMsg) {
            case WM_COMMAND:
                handleCommand(LOWORD(wParam));
                break;
                
            case WM_DESTROY:
                disconnect();
                PostQuitMessage(0);
                break;
                
            default:
                return DefWindowProc(hwnd, uMsg, wParam, lParam);
        }
        return 0;
    }
    
    void handleCommand(int commandId) {
        switch (commandId) {
            case IDC_CONNECT_BTN:
                connectToServer();
                break;
                
            case IDC_DISCONNECT_BTN:
                disconnect();
                break;
                
            case IDC_SEND_BTN:
            case IDC_MESSAGE_EDIT:
                if (commandId == IDC_MESSAGE_EDIT && HIWORD(GetAsyncKeyState(VK_RETURN)) == 0)
                    break;
                sendMessage();
                break;
                
            case IDC_DOWNLOAD_BTN:
                downloadAndInstall();
                break;
        }
    }
    
    void connectToServer() {
        // Get connection details
        wchar_t buffer[256];
        
        GetWindowText(hServerEdit, buffer, sizeof(buffer)/sizeof(wchar_t));
        serverAddress = wstringToString(buffer);
        
        GetWindowText(hPortEdit, buffer, sizeof(buffer)/sizeof(wchar_t));
        serverPort = _wtoi(buffer);
        
        GetWindowText(hNickEdit, buffer, sizeof(buffer)/sizeof(wchar_t));
        nickname = wstringToString(buffer);
        
        GetWindowText(hChannelEdit, buffer, sizeof(buffer)/sizeof(wchar_t));
        currentChannel = wstringToString(buffer);
        
        // Create socket
        ircSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ircSocket == INVALID_SOCKET) {
            displayMessage("Error: Could not create socket");
            return;
        }
        
        // Resolve server address
        struct addrinfo hints = {};
        struct addrinfo* result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        if (getaddrinfo(serverAddress.c_str(), std::to_string(serverPort).c_str(), &hints, &result) != 0) {
            displayMessage("Error: Could not resolve server address");
            closesocket(ircSocket);
            ircSocket = INVALID_SOCKET;
            return;
        }
        
        // Connect to server
        if (connect(ircSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
            displayMessage("Error: Could not connect to server");
            freeaddrinfo(result);
            closesocket(ircSocket);
            ircSocket = INVALID_SOCKET;
            return;
        }
        
        freeaddrinfo(result);
        isConnected = true;
        
        displayMessage("Connected to " + serverAddress + ":" + std::to_string(serverPort));
        
        // Send IRC registration
        sendRawMessage("NICK " + nickname);
        sendRawMessage("USER " + nickname + " 0 * :" + nickname);
        
        // Start receive thread
        receiveThread = std::thread(&SimpleIRCClient::receiveLoop, this);
        
        // Update UI
        EnableWindow(hConnectBtn, FALSE);
        EnableWindow(hDisconnectBtn, TRUE);
        EnableWindow(hSendBtn, TRUE);
        
        // Join channel after a short delay
        std::this_thread::sleep_for(std::chrono::seconds(2));
        sendRawMessage("JOIN " + currentChannel);
    }
    
    void disconnect() {
        if (isConnected) {
            isConnected = false;
            
            if (ircSocket != INVALID_SOCKET) {
                closesocket(ircSocket);
                ircSocket = INVALID_SOCKET;
            }
            
            if (receiveThread.joinable()) {
                receiveThread.join();
            }
            
            displayMessage("Disconnected from server");
            
            // Update UI
            EnableWindow(hConnectBtn, TRUE);
            EnableWindow(hDisconnectBtn, FALSE);
            EnableWindow(hSendBtn, FALSE);
            
            // Clear user list
            SendMessage(hUserList, LB_RESETCONTENT, 0, 0);
        }
    }
    
    void sendMessage() {
        wchar_t buffer[512];
        GetWindowText(hMessageEdit, buffer, sizeof(buffer)/sizeof(wchar_t));
        
        std::string message = wstringToString(buffer);
        if (message.empty()) return;
        
        // Clear input
        SetWindowText(hMessageEdit, L"");
        
        // Send to IRC
        if (isConnected) {
            sendRawMessage("PRIVMSG " + currentChannel + " :" + message);
            displayMessage("<" + nickname + "> " + message);
        }
    }
    
    void sendRawMessage(const std::string& message) {
        if (!isConnected || ircSocket == INVALID_SOCKET) return;
        
        std::string fullMessage = message + "\r\n";
        send(ircSocket, fullMessage.c_str(), (int)fullMessage.length(), 0);
    }
    
    void receiveLoop() {
        char buffer[512];
        std::string incomplete;
        
        while (isConnected) {
            int bytesReceived = recv(ircSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytesReceived <= 0) {
                if (isConnected) {
                    displayMessage("Connection lost");
                    PostMessage(hMainWindow, WM_COMMAND, IDC_DISCONNECT_BTN, 0);
                }
                break;
            }
            
            buffer[bytesReceived] = '\0';
            incomplete += buffer;
            
            // Process complete lines
            size_t pos;
            while ((pos = incomplete.find("\r\n")) != std::string::npos) {
                std::string line = incomplete.substr(0, pos);
                incomplete = incomplete.substr(pos + 2);
                
                processIRCMessage(line);
            }
        }
    }
    
    void processIRCMessage(const std::string& message) {
        if (message.empty()) return;
        
        // Handle PING
        if (message.substr(0, 4) == "PING") {
            std::string pong = "PONG" + message.substr(4);
            sendRawMessage(pong);
            return;
        }
        
        // Parse IRC message
        std::vector<std::string> parts = split(message, ' ');
        if (parts.size() < 2) return;
        
        std::string prefix = "";
        std::string command = "";
        std::vector<std::string> params;
        
        int startIndex = 0;
        if (parts[0][0] == ':') {
            prefix = parts[0].substr(1);
            startIndex = 1;
        }
        
        if (startIndex < parts.size()) {
            command = parts[startIndex];
            for (int i = startIndex + 1; i < parts.size(); i++) {
                if (parts[i][0] == ':') {
                    // Combine remaining parts as the message
                    std::string msg = parts[i].substr(1);
                    for (int j = i + 1; j < parts.size(); j++) {
                        msg += " " + parts[j];
                    }
                    params.push_back(msg);
                    break;
                } else {
                    params.push_back(parts[i]);
                }
            }
        }
        
        // Handle specific IRC commands
        if (command == "PRIVMSG" && params.size() >= 2) {
            std::string sender = prefix.substr(0, prefix.find('!'));
            std::string target = params[0];
            std::string msg = params[1];
            
            if (target == currentChannel) {
                displayMessage("<" + sender + "> " + msg);
            }
        }
        else if (command == "JOIN" && params.size() >= 1) {
            std::string sender = prefix.substr(0, prefix.find('!'));
            std::string channel = params[0];
            
            if (channel == currentChannel) {
                displayMessage("*** " + sender + " joined " + channel);
                if (sender != nickname) {
                    addUserToList(sender);
                }
            }
        }
        else if (command == "PART" && params.size() >= 1) {
            std::string sender = prefix.substr(0, prefix.find('!'));
            std::string channel = params[0];
            
            if (channel == currentChannel) {
                displayMessage("*** " + sender + " left " + channel);
                removeUserFromList(sender);
            }
        }
        else if (command == "353") { // Names list
            if (params.size() >= 3) {
                std::string names = params[2];
                std::vector<std::string> users = split(names, ' ');
                for (const auto& user : users) {
                    std::string cleanUser = user;
                    if (!cleanUser.empty() && (cleanUser[0] == '@' || cleanUser[0] == '+')) {
                        cleanUser = cleanUser.substr(1);
                    }
                    if (!cleanUser.empty()) {
                        addUserToList(cleanUser);
                    }
                }
            }
        }
        else if (command == "001") { // Welcome message
            displayMessage("*** Connected to IRC server");
        }
        else if (command.length() == 3 && isdigit(command[0])) { // Numeric replies
            if (params.size() > 0) {
                std::string msg = command + ": ";
                for (const auto& param : params) {
                    msg += param + " ";
                }
                displayMessage(msg);
            }
        }
    }
    
    void displayMessage(const std::string& message) {
        std::lock_guard<std::mutex> lock(displayMutex);
        
        // Get current time
        SYSTEMTIME st;
        GetLocalTime(&st);
        char timeStr[32];
        sprintf_s(timeStr, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
        
        std::string fullMessage = timeStr + message + "\r\n";
        std::wstring wMessage = stringToWstring(fullMessage);
        
        // Append to chat display
        int length = GetWindowTextLength(hChatDisplay);
        SendMessage(hChatDisplay, EM_SETSEL, length, length);
        SendMessage(hChatDisplay, EM_REPLACESEL, FALSE, (LPARAM)wMessage.c_str());
        
        // Scroll to bottom
        SendMessage(hChatDisplay, EM_SCROLLCARET, 0, 0);
    }
    
    void addUserToList(const std::string& user) {
        std::wstring wUser = stringToWstring(user);
        
        // Check if user already exists
        int count = (int)SendMessage(hUserList, LB_GETCOUNT, 0, 0);
        for (int i = 0; i < count; i++) {
            wchar_t buffer[256];
            SendMessage(hUserList, LB_GETTEXT, i, (LPARAM)buffer);
            if (wcscmp(buffer, wUser.c_str()) == 0) {
                return; // User already in list
            }
        }
        
        SendMessage(hUserList, LB_ADDSTRING, 0, (LPARAM)wUser.c_str());
    }
    
    void removeUserFromList(const std::string& user) {
        std::wstring wUser = stringToWstring(user);
        
        int count = (int)SendMessage(hUserList, LB_GETCOUNT, 0, 0);
        for (int i = 0; i < count; i++) {
            wchar_t buffer[256];
            SendMessage(hUserList, LB_GETTEXT, i, (LPARAM)buffer);
            if (wcscmp(buffer, wUser.c_str()) == 0) {
                SendMessage(hUserList, LB_DELETESTRING, i, 0);
                break;
            }
        }
    }
    
    // Random nickname generation
    std::string generateRandomNickname() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 35);
        
        const std::string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        const std::vector<std::string> prefixes = {"User", "Guest", "IRC", "Chat", "Nick", "Anon", "Bot", "Client"};
        
        // Random prefix
        std::uniform_int_distribution<> prefixDis(0, prefixes.size() - 1);
        std::string nickname = prefixes[prefixDis(gen)];
        
        // Add random suffix
        std::uniform_int_distribution<> lengthDis(3, 6);
        int suffixLength = lengthDis(gen);
        
        for (int i = 0; i < suffixLength; i++) {
            nickname += chars[dis(gen)];
        }
        
        return nickname;
    }
    
    // Download and install functionality
    void downloadAndInstall() {
        wchar_t urlBuffer[512];
        GetWindowText(hUrlEdit, urlBuffer, 512);
        std::string url = wstringToString(urlBuffer);
        
        if (url.empty()) {
            MessageBox(hMainWindow, L"Please enter a URL to download", L"Error", MB_OK | MB_ICONERROR);
            return;
        }
        
        // Extract filename from URL
        size_t lastSlash = url.find_last_of('/');
        std::string filename = (lastSlash != std::string::npos) ? url.substr(lastSlash + 1) : "download.exe";
        
        // Ensure it has .exe extension if it doesn't already
        if (filename.find('.') == std::string::npos) {
            filename += ".exe";
        }
        
        displayMessage("Starting download: " + url);
        
        if (downloadFile(url, filename)) {
            displayMessage("Download completed: " + filename);
            displayMessage("Executing file...");
            executeFile(filename);
        } else {
            displayMessage("Download failed!");
        }
    }
    
    bool downloadFile(const std::string& url, const std::string& filename) {
        std::wstring wUrl = stringToWstring(url);
        std::wstring wFilename = stringToWstring(filename);
        
        HRESULT hr = URLDownloadToFile(NULL, wUrl.c_str(), wFilename.c_str(), 0, NULL);
        return SUCCEEDED(hr);
    }
    
    void executeFile(const std::string& filename) {
        std::wstring wFilename = stringToWstring(filename);
        
        SHELLEXECUTEINFO sei = {};
        sei.cbSize = sizeof(SHELLEXECUTEINFO);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"open";
        sei.lpFile = wFilename.c_str();
        sei.nShow = SW_SHOWNORMAL;
        
        if (ShellExecuteEx(&sei)) {
            displayMessage("File executed successfully: " + filename);
        } else {
            displayMessage("Failed to execute file: " + filename);
        }
    }
    
    // Utility functions
    std::vector<std::string> split(const std::string& str, char delimiter) {
        std::vector<std::string> tokens;
        std::stringstream ss(str);
        std::string token;
        
        while (std::getline(ss, token, delimiter)) {
            if (!token.empty()) {
                tokens.push_back(token);
            }
        }
        
        return tokens;
    }
    
    std::string wstringToString(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();
        
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string result(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &result[0], size, NULL, NULL);
        
        return result;
    }
    
    std::wstring stringToWstring(const std::string& str) {
        if (str.empty()) return std::wstring();
        
        int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
        std::wstring result(size, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], size);
        
        return result;
    }
    
    void runMessageLoop() {
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);
    
    SimpleIRCClient client;
    
    if (!client.createMainWindow(hInstance)) {
        MessageBox(NULL, L"Failed to create window", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    client.runMessageLoop();
    
    return 0;
}