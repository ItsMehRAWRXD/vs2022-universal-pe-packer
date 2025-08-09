// BlackMamba IRC Bot - Remote Compilation via IRC
// 🐍 Compile code through IRC channels using BlackMagii backend
// Supports all languages including mIRC scripting!

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <thread>
#include <mutex>
#include <chrono>
#include <fstream>
#include <sstream>
#include <regex>
#include <random>

// Network includes
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

// HTTP client for BlackMagii server
#include <curl/curl.h>

class BlackMambaBot {
private:
    // IRC Connection
    struct IRCConfig {
        std::string server = "irc.libera.chat";
        int port = 6667;
        std::string nick = "BlackMamba";
        std::string channel = "#blackmagii";
        std::string password = "";
        std::string blackMagiiServer = "http://localhost:8888";
    };
    
    IRCConfig config;
    int sockfd;
    bool connected = false;
    
    // Code submission tracking
    struct CodeSubmission {
        std::string user;
        std::string language;
        std::string code;
        std::vector<std::string> platforms;
        std::string submissionId;
        std::chrono::system_clock::time_point timestamp;
    };
    
    std::map<std::string, CodeSubmission> activeSubmissions;
    std::mutex submissionMutex;
    
    // Language definitions with mIRC!
    std::map<std::string, std::string> languageMap = {
        {"cpp", "C++"},
        {"c++", "C++"},
        {"c", "C"},
        {"python", "Python"},
        {"py", "Python"},
        {"java", "Java"},
        {"rust", "Rust"},
        {"rs", "Rust"},
        {"go", "Go"},
        {"js", "JavaScript"},
        {"javascript", "JavaScript"},
        {"mirc", "mIRC"},
        {"msl", "mIRC"},
        {"autoit", "AutoIt"},
        {"au3", "AutoIt"},
        {"asm", "Assembly"},
        {"assembly", "Assembly"}
    };
    
    // IRC color codes
    const std::string COLOR_GREEN = "\x0303";
    const std::string COLOR_RED = "\x0304";
    const std::string COLOR_BLUE = "\x0302";
    const std::string COLOR_YELLOW = "\x0308";
    const std::string COLOR_RESET = "\x0F";
    const std::string BOLD = "\x02";
    
public:
    BlackMambaBot(const std::string& configFile = "") {
        if (!configFile.empty()) {
            loadConfig(configFile);
        }
    }
    
    void start() {
        std::cout << "🐍 BlackMamba IRC Bot Starting..." << std::endl;
        
        // Connect to IRC
        if (!connectToIRC()) {
            std::cerr << "Failed to connect to IRC server!" << std::endl;
            return;
        }
        
        // Start message handler
        std::thread messageHandler([this]() {
            handleMessages();
        });
        
        // Start compilation result checker
        std::thread resultChecker([this]() {
            checkCompilationResults();
        });
        
        messageHandler.join();
        resultChecker.join();
    }
    
private:
    bool connectToIRC() {
        // Create socket
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return false;
        
        // Resolve hostname
        struct hostent* server = gethostbyname(config.server.c_str());
        if (!server) return false;
        
        // Connect
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(config.port);
        memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        
        if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            return false;
        }
        
        // Send NICK and USER
        sendRaw("NICK " + config.nick);
        sendRaw("USER " + config.nick + " 0 * :BlackMamba Compilation Bot");
        
        // Wait for connection
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Join channel
        sendRaw("JOIN " + config.channel);
        
        connected = true;
        
        // Send welcome message
        std::this_thread::sleep_for(std::chrono::seconds(1));
        sendMessage(config.channel, BOLD + "🐍 BlackMamba Online!" + BOLD + " - Remote compilation service powered by BlackMagii 🎩✨");
        sendMessage(config.channel, "Type " + COLOR_GREEN + "!compile help" + COLOR_RESET + " for commands");
        
        return true;
    }
    
    void handleMessages() {
        char buffer[4096];
        
        while (connected) {
            memset(buffer, 0, sizeof(buffer));
            int n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            
            if (n <= 0) {
                connected = false;
                break;
            }
            
            std::string message(buffer);
            std::istringstream iss(message);
            std::string line;
            
            while (std::getline(iss, line)) {
                handleIRCMessage(line);
            }
        }
    }
    
    void handleIRCMessage(const std::string& message) {
        // Handle PING
        if (message.find("PING :") == 0) {
            sendRaw("PONG :" + message.substr(6));
            return;
        }
        
        // Parse PRIVMSG
        std::regex privmsgRegex(":([^!]+)![^ ]+ PRIVMSG ([^ ]+) :(.*)");
        std::smatch matches;
        
        if (std::regex_match(message, matches, privmsgRegex)) {
            std::string nick = matches[1];
            std::string target = matches[2];
            std::string msg = matches[3];
            
            // Remove \r if present
            if (!msg.empty() && msg.back() == '\r') {
                msg.pop_back();
            }
            
            handleCommand(nick, target, msg);
        }
    }
    
    void handleCommand(const std::string& nick, const std::string& target, const std::string& message) {
        // Determine reply target
        std::string replyTo = (target == config.nick) ? nick : target;
        
        // Command parsing
        if (message.find("!compile") == 0) {
            handleCompileCommand(nick, replyTo, message.substr(8));
        }
        else if (message.find("!status") == 0) {
            handleStatusCommand(nick, replyTo, message.substr(7));
        }
        else if (message.find("!download") == 0) {
            handleDownloadCommand(nick, replyTo, message.substr(9));
        }
        else if (message.find("!languages") == 0) {
            showLanguages(replyTo);
        }
        else if (message.find("!platforms") == 0) {
            showPlatforms(replyTo);
        }
        else if (message.find("!about") == 0) {
            showAbout(replyTo);
        }
    }
    
    void handleCompileCommand(const std::string& nick, const std::string& replyTo, const std::string& args) {
        std::istringstream iss(args);
        std::string subcommand;
        iss >> subcommand;
        
        if (subcommand.empty() || subcommand == "help") {
            showCompileHelp(replyTo);
        }
        else if (subcommand == "url") {
            handleCompileFromURL(nick, replyTo, args.substr(4));
        }
        else if (subcommand == "paste") {
            handleCompileFromPaste(nick, replyTo, args.substr(6));
        }
        else if (subcommand == "quick") {
            handleQuickCompile(nick, replyTo, args.substr(6));
        }
        else if (subcommand == "mirc") {
            handleMircCompile(nick, replyTo, args.substr(5));
        }
        else {
            // Assume it's a language name
            handleDirectCompile(nick, replyTo, args);
        }
    }
    
    void handleDirectCompile(const std::string& nick, const std::string& replyTo, const std::string& args) {
        // Parse: !compile <language> <platforms> <code>
        std::istringstream iss(args);
        std::string language, platformStr;
        iss >> language >> platformStr;
        
        // Get the rest as code
        std::string code;
        std::getline(iss, code);
        code = trim(code);
        
        // Validate language
        std::string normalizedLang = normalizeLanguage(language);
        if (normalizedLang.empty()) {
            sendMessage(replyTo, COLOR_RED + "❌ Unknown language: " + language + COLOR_RESET);
            sendMessage(replyTo, "Supported: C++, C, Python, Java, Rust, Go, JavaScript, mIRC, AutoIt, Assembly");
            return;
        }
        
        // Parse platforms
        std::vector<std::string> platforms = parsePlatforms(platformStr);
        if (platforms.empty()) {
            sendMessage(replyTo, COLOR_RED + "❌ Invalid platforms. Use: windows,linux,macos,android or 'all'" + COLOR_RESET);
            return;
        }
        
        // Generate submission ID
        std::string submissionId = generateSubmissionId();
        
        // Store submission
        {
            std::lock_guard<std::mutex> lock(submissionMutex);
            activeSubmissions[submissionId] = {
                nick, normalizedLang, code, platforms, submissionId,
                std::chrono::system_clock::now()
            };
        }
        
        // Send to BlackMagii
        sendMessage(replyTo, COLOR_GREEN + "🚀 Compiling " + normalizedLang + " for " + 
                   std::to_string(platforms.size()) + " platform(s)..." + COLOR_RESET);
        sendMessage(replyTo, "ID: " + COLOR_BLUE + submissionId + COLOR_RESET);
        
        submitToBlackMagii(submissionId);
    }
    
    void handleMircCompile(const std::string& nick, const std::string& replyTo, const std::string& code) {
        // Special handler for mIRC scripts
        sendMessage(replyTo, COLOR_BLUE + "🎭 mIRC Script Compilation" + COLOR_RESET);
        
        std::string submissionId = generateSubmissionId();
        
        // mIRC scripts are special - they're interpreted, not compiled
        // But we can validate syntax and create distribution packages
        
        {
            std::lock_guard<std::mutex> lock(submissionMutex);
            activeSubmissions[submissionId] = {
                nick, "mIRC", code, {"mIRC"}, submissionId,
                std::chrono::system_clock::now()
            };
        }
        
        // Validate mIRC syntax
        if (validateMircScript(code)) {
            sendMessage(replyTo, COLOR_GREEN + "✅ mIRC script syntax valid!" + COLOR_RESET);
            
            // Create packaged version
            std::string packageUrl = createMircPackage(submissionId, code);
            sendMessage(replyTo, "📦 Download: " + packageUrl);
            
            // Show preview
            showMircPreview(replyTo, code);
        } else {
            sendMessage(replyTo, COLOR_RED + "❌ mIRC script has syntax errors!" + COLOR_RESET);
        }
    }
    
    void handleQuickCompile(const std::string& nick, const std::string& replyTo, const std::string& args) {
        // Quick compile for one-liners
        // Format: !compile quick <language> <code>
        std::istringstream iss(args);
        std::string language;
        iss >> language;
        
        std::string code;
        std::getline(iss, code);
        code = trim(code);
        
        // Wrap code in appropriate boilerplate
        std::string fullCode = wrapCodeBoilerplate(language, code);
        
        // Compile for current platform only
        handleDirectCompile(nick, replyTo, language + " current " + fullCode);
    }
    
    void submitToBlackMagii(const std::string& submissionId) {
        std::thread([this, submissionId]() {
            CodeSubmission submission;
            {
                std::lock_guard<std::mutex> lock(submissionMutex);
                submission = activeSubmissions[submissionId];
            }
            
            // Prepare JSON request
            std::string jsonRequest = createCompilationRequest(submission);
            
            // Send to BlackMagii server
            CURL* curl = curl_easy_init();
            if (curl) {
                std::string response;
                
                curl_easy_setopt(curl, CURLOPT_URL, 
                                (config.blackMagiiServer + "/api/compile").c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonRequest.c_str());
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
                
                struct curl_slist* headers = nullptr;
                headers = curl_slist_append(headers, "Content-Type: application/json");
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
                
                CURLcode res = curl_easy_perform(curl);
                
                if (res == CURLE_OK) {
                    // Parse response and update submission
                    updateSubmissionStatus(submissionId, response);
                } else {
                    notifyError(submissionId, "Failed to connect to BlackMagii server");
                }
                
                curl_slist_free_all(headers);
                curl_easy_cleanup(curl);
            }
        }).detach();
    }
    
    std::string createCompilationRequest(const CodeSubmission& submission) {
        std::ostringstream json;
        json << "{";
        json << "\"language\":\"" << submission.language << "\",";
        json << "\"code\":\"" << escapeJson(submission.code) << "\",";
        json << "\"platforms\":[";
        
        for (size_t i = 0; i < submission.platforms.size(); i++) {
            json << "\"" << submission.platforms[i] << "\"";
            if (i < submission.platforms.size() - 1) json << ",";
        }
        
        json << "],";
        json << "\"submissionId\":\"" << submission.submissionId << "\"";
        json << "}";
        
        return json.str();
    }
    
    void showCompileHelp(const std::string& replyTo) {
        sendMessage(replyTo, BOLD + "🐍 BlackMamba Compilation Commands:" + BOLD);
        sendMessage(replyTo, COLOR_GREEN + "!compile <lang> <platforms> <code>" + COLOR_RESET + 
                           " - Compile inline code");
        sendMessage(replyTo, COLOR_GREEN + "!compile url <url>" + COLOR_RESET + 
                           " - Compile from URL");
        sendMessage(replyTo, COLOR_GREEN + "!compile paste <pastebin>" + COLOR_RESET + 
                           " - Compile from paste service");
        sendMessage(replyTo, COLOR_GREEN + "!compile quick <lang> <one-liner>" + COLOR_RESET + 
                           " - Quick compile with boilerplate");
        sendMessage(replyTo, COLOR_GREEN + "!compile mirc <script>" + COLOR_RESET + 
                           " - Validate and package mIRC script");
        sendMessage(replyTo, "Platforms: " + COLOR_BLUE + "windows, linux, macos, android, all" + COLOR_RESET);
        sendMessage(replyTo, "Example: " + COLOR_YELLOW + "!compile cpp all cout<<\"Hello!\";" + COLOR_RESET);
    }
    
    void showLanguages(const std::string& replyTo) {
        sendMessage(replyTo, BOLD + "🗣️ Supported Languages:" + BOLD);
        
        std::string langs = "";
        for (const auto& [key, value] : languageMap) {
            if (langs.find(value) == std::string::npos) {
                if (!langs.empty()) langs += ", ";
                langs += COLOR_BLUE + value + COLOR_RESET;
            }
        }
        
        sendMessage(replyTo, langs);
        sendMessage(replyTo, "Including " + COLOR_GREEN + "mIRC scripting!" + COLOR_RESET + " 🎭");
    }
    
    bool validateMircScript(const std::string& script) {
        // Basic mIRC script validation
        int braceCount = 0;
        bool inComment = false;
        
        std::istringstream iss(script);
        std::string line;
        
        while (std::getline(iss, line)) {
            // Skip comments
            if (line.find(';') == 0) continue;
            
            // Count braces
            for (char c : line) {
                if (c == '{') braceCount++;
                else if (c == '}') braceCount--;
            }
            
            // Check for common mIRC commands
            if (line.find("on ") == 0 || line.find("alias ") == 0) {
                // Valid mIRC event/alias
            }
        }
        
        return braceCount == 0;
    }
    
    std::string wrapCodeBoilerplate(const std::string& language, const std::string& code) {
        std::string lang = normalizeLanguage(language);
        
        if (lang == "C++") {
            return "#include <iostream>\nusing namespace std;\nint main() { " + code + " return 0; }";
        }
        else if (lang == "C") {
            return "#include <stdio.h>\nint main() { " + code + " return 0; }";
        }
        else if (lang == "Python") {
            return code; // Python doesn't need boilerplate
        }
        else if (lang == "Java") {
            return "public class Main { public static void main(String[] args) { " + code + " } }";
        }
        else if (lang == "JavaScript") {
            return code; // JS doesn't need boilerplate
        }
        else if (lang == "mIRC") {
            return "alias quicktest { " + code + " }";
        }
        
        return code;
    }
    
    void sendMessage(const std::string& target, const std::string& message) {
        // Split long messages
        const size_t maxLen = 400;
        if (message.length() > maxLen) {
            size_t pos = 0;
            while (pos < message.length()) {
                std::string part = message.substr(pos, maxLen);
                sendRaw("PRIVMSG " + target + " :" + part);
                pos += maxLen;
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        } else {
            sendRaw("PRIVMSG " + target + " :" + message);
        }
    }
    
    void sendRaw(const std::string& message) {
        std::string msg = message + "\r\n";
        send(sockfd, msg.c_str(), msg.length(), 0);
    }
    
    std::string normalizeLanguage(const std::string& lang) {
        std::string lower = lang;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        
        auto it = languageMap.find(lower);
        if (it != languageMap.end()) {
            return it->second;
        }
        
        return "";
    }
    
    std::vector<std::string> parsePlatforms(const std::string& platformStr) {
        std::vector<std::string> platforms;
        
        if (platformStr == "all") {
            return {"Windows", "Linux", "macOS", "Android"};
        }
        
        if (platformStr == "current") {
            #ifdef _WIN32
                return {"Windows"};
            #elif __APPLE__
                return {"macOS"};
            #elif __linux__
                return {"Linux"};
            #else
                return {"Linux"};
            #endif
        }
        
        // Parse comma-separated list
        std::istringstream iss(platformStr);
        std::string platform;
        
        while (std::getline(iss, platform, ',')) {
            platform = trim(platform);
            std::transform(platform.begin(), platform.end(), platform.begin(), ::tolower);
            
            if (platform == "windows" || platform == "win") {
                platforms.push_back("Windows");
            }
            else if (platform == "linux" || platform == "lin") {
                platforms.push_back("Linux");
            }
            else if (platform == "macos" || platform == "mac" || platform == "osx") {
                platforms.push_back("macOS");
            }
            else if (platform == "android" || platform == "droid") {
                platforms.push_back("Android");
            }
        }
        
        return platforms;
    }
    
    std::string generateSubmissionId() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        std::string id = "BM";
        for (int i = 0; i < 6; i++) {
            int n = dis(gen);
            id += "0123456789ABCDEF"[n];
        }
        
        return id;
    }
    
    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\n\r");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\n\r");
        return str.substr(first, (last - first + 1));
    }
    
    std::string escapeJson(const std::string& str) {
        std::string escaped;
        for (char c : str) {
            switch (c) {
                case '"': escaped += "\\\""; break;
                case '\\': escaped += "\\\\"; break;
                case '\n': escaped += "\\n"; break;
                case '\r': escaped += "\\r"; break;
                case '\t': escaped += "\\t"; break;
                default: escaped += c;
            }
        }
        return escaped;
    }
    
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }
    
    void checkCompilationResults() {
        while (connected) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            // Check for completed compilations
            std::lock_guard<std::mutex> lock(submissionMutex);
            
            for (auto& [id, submission] : activeSubmissions) {
                // Check if compilation is done
                // In real implementation, poll BlackMagii server
            }
        }
    }
    
    void showMircPreview(const std::string& replyTo, const std::string& script) {
        sendMessage(replyTo, "📝 mIRC Script Preview:");
        
        std::istringstream iss(script);
        std::string line;
        int lineCount = 0;
        
        while (std::getline(iss, line) && lineCount < 3) {
            sendMessage(replyTo, COLOR_YELLOW + line + COLOR_RESET);
            lineCount++;
        }
        
        if (lineCount >= 3) {
            sendMessage(replyTo, "... (truncated)");
        }
    }
    
    std::string createMircPackage(const std::string& submissionId, const std::string& script) {
        // Create a packaged mIRC script with installer
        std::string filename = "mircscript_" + submissionId + ".mrc";
        std::ofstream out(filename);
        
        // Add header
        out << "; BlackMamba Compiled mIRC Script" << std::endl;
        out << "; Generated: " << getCurrentTime() << std::endl;
        out << "; Submission ID: " << submissionId << std::endl;
        out << std::endl;
        
        // Add the script
        out << script << std::endl;
        
        // Add auto-installer
        out << std::endl;
        out << "; Auto-installer" << std::endl;
        out << "on *:LOAD: {" << std::endl;
        out << "  echo -a 4*** BlackMamba mIRC Script Loaded! ***" << std::endl;
        out << "  echo -a 3*** Type /bmhelp for commands ***" << std::endl;
        out << "}" << std::endl;
        
        out.close();
        
        // Return download URL
        return config.blackMagiiServer + "/download/" + filename;
    }
    
    std::string getCurrentTime() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        char buffer[100];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&time_t));
        return std::string(buffer);
    }
    
    void showAbout(const std::string& replyTo) {
        sendMessage(replyTo, BOLD + "🐍 BlackMamba IRC Compilation Bot" + BOLD);
        sendMessage(replyTo, "Powered by " + COLOR_BLUE + "BlackMagii" + COLOR_RESET + 
                           " 🎩✨ - The Swiss Army Knife of Compilers");
        sendMessage(replyTo, "Supports: C++, C, Python, Java, Rust, Go, JavaScript, " +
                           COLOR_GREEN + "mIRC" + COLOR_RESET + ", AutoIt, Assembly");
        sendMessage(replyTo, "Features: Cross-compilation, tinyRAWR compression, " +
                           "remote execution, syntax validation");
        sendMessage(replyTo, "GitHub: https://github.com/ItsMehRAWRXD/BlackMagii");
    }
    
    void loadConfig(const std::string& configFile) {
        std::ifstream file(configFile);
        if (!file) return;
        
        std::string line;
        while (std::getline(file, line)) {
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = trim(line.substr(0, pos));
                std::string value = trim(line.substr(pos + 1));
                
                if (key == "server") config.server = value;
                else if (key == "port") config.port = std::stoi(value);
                else if (key == "nick") config.nick = value;
                else if (key == "channel") config.channel = value;
                else if (key == "password") config.password = value;
                else if (key == "blackmagii") config.blackMagiiServer = value;
            }
        }
    }
    
    void notifyError(const std::string& submissionId, const std::string& error) {
        // Find the user who submitted this
        std::string user;
        {
            std::lock_guard<std::mutex> lock(submissionMutex);
            auto it = activeSubmissions.find(submissionId);
            if (it != activeSubmissions.end()) {
                user = it->second.user;
            }
        }
        
        if (!user.empty()) {
            sendMessage(config.channel, user + ": " + COLOR_RED + "❌ Error with " + 
                       submissionId + ": " + error + COLOR_RESET);
        }
    }
    
    void handleStatusCommand(const std::string& nick, const std::string& replyTo, const std::string& args) {
        std::string submissionId = trim(args);
        
        if (submissionId.empty()) {
            // Show all active submissions for this user
            showUserSubmissions(nick, replyTo);
        } else {
            // Show specific submission status
            showSubmissionStatus(submissionId, replyTo);
        }
    }
    
    void handleDownloadCommand(const std::string& nick, const std::string& replyTo, const std::string& args) {
        std::string submissionId = trim(args);
        
        if (submissionId.empty()) {
            sendMessage(replyTo, COLOR_RED + "Usage: !download <submission_id>" + COLOR_RESET);
            return;
        }
        
        // Get download links from BlackMagii
        std::string downloadUrl = config.blackMagiiServer + "/download/" + submissionId;
        sendMessage(replyTo, "📦 Download compiled binaries: " + COLOR_BLUE + downloadUrl + COLOR_RESET);
        sendMessage(replyTo, "🦖 tinyRAWR archive: " + COLOR_BLUE + downloadUrl + ".rawr" + COLOR_RESET);
    }
    
    void showUserSubmissions(const std::string& nick, const std::string& replyTo) {
        std::lock_guard<std::mutex> lock(submissionMutex);
        
        std::vector<std::string> userSubmissions;
        for (const auto& [id, submission] : activeSubmissions) {
            if (submission.user == nick) {
                userSubmissions.push_back(id);
            }
        }
        
        if (userSubmissions.empty()) {
            sendMessage(replyTo, nick + ": You have no active submissions.");
        } else {
            sendMessage(replyTo, nick + ": Your active submissions: " + 
                       COLOR_BLUE + join(userSubmissions, ", ") + COLOR_RESET);
        }
    }
    
    void showSubmissionStatus(const std::string& submissionId, const std::string& replyTo) {
        std::lock_guard<std::mutex> lock(submissionMutex);
        
        auto it = activeSubmissions.find(submissionId);
        if (it == activeSubmissions.end()) {
            sendMessage(replyTo, COLOR_RED + "Unknown submission ID: " + submissionId + COLOR_RESET);
            return;
        }
        
        const auto& submission = it->second;
        sendMessage(replyTo, "📊 Submission " + COLOR_BLUE + submissionId + COLOR_RESET);
        sendMessage(replyTo, "Language: " + submission.language + 
                           " | Platforms: " + join(submission.platforms, ", "));
        sendMessage(replyTo, "Status: " + COLOR_YELLOW + "Compiling..." + COLOR_RESET);
    }
    
    std::string join(const std::vector<std::string>& vec, const std::string& delimiter) {
        std::string result;
        for (size_t i = 0; i < vec.size(); i++) {
            result += vec[i];
            if (i < vec.size() - 1) result += delimiter;
        }
        return result;
    }
    
    void updateSubmissionStatus(const std::string& submissionId, const std::string& response) {
        // Parse response and notify user
        // In real implementation, parse JSON response
        
        std::lock_guard<std::mutex> lock(submissionMutex);
        auto it = activeSubmissions.find(submissionId);
        if (it != activeSubmissions.end()) {
            sendMessage(config.channel, it->second.user + ": " + 
                       COLOR_GREEN + "✅ Compilation complete for " + submissionId + COLOR_RESET);
            sendMessage(config.channel, "Download: " + COLOR_BLUE + 
                       config.blackMagiiServer + "/download/" + submissionId + COLOR_RESET);
        }
    }
    
    void handleCompileFromURL(const std::string& nick, const std::string& replyTo, const std::string& url) {
        sendMessage(replyTo, COLOR_YELLOW + "📥 Fetching code from URL..." + COLOR_RESET);
        
        // Download code from URL
        CURL* curl = curl_easy_init();
        if (curl) {
            std::string code;
            
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &code);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            
            CURLcode res = curl_easy_perform(curl);
            
            if (res == CURLE_OK) {
                // Detect language from URL or content
                std::string language = detectLanguageFromURL(url);
                
                if (language.empty()) {
                    sendMessage(replyTo, COLOR_RED + "❌ Could not detect language from URL" + COLOR_RESET);
                } else {
                    handleDirectCompile(nick, replyTo, language + " all " + code);
                }
            } else {
                sendMessage(replyTo, COLOR_RED + "❌ Failed to fetch URL" + COLOR_RESET);
            }
            
            curl_easy_cleanup(curl);
        }
    }
    
    std::string detectLanguageFromURL(const std::string& url) {
        // Simple detection based on file extension
        if (url.find(".cpp") != std::string::npos) return "cpp";
        if (url.find(".c") != std::string::npos) return "c";
        if (url.find(".py") != std::string::npos) return "python";
        if (url.find(".java") != std::string::npos) return "java";
        if (url.find(".rs") != std::string::npos) return "rust";
        if (url.find(".go") != std::string::npos) return "go";
        if (url.find(".js") != std::string::npos) return "javascript";
        if (url.find(".mrc") != std::string::npos) return "mirc";
        if (url.find(".au3") != std::string::npos) return "autoit";
        
        return "";
    }
    
    void handleCompileFromPaste(const std::string& nick, const std::string& replyTo, const std::string& pasteId) {
        // Support various paste services
        std::vector<std::string> pasteUrls = {
            "https://pastebin.com/raw/" + pasteId,
            "https://hastebin.com/raw/" + pasteId,
            "https://paste.rs/" + pasteId + ".txt"
        };
        
        for (const auto& url : pasteUrls) {
            // Try each paste service
            CURL* curl = curl_easy_init();
            if (curl) {
                std::string code;
                
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &code);
                
                CURLcode res = curl_easy_perform(curl);
                long httpCode = 0;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
                
                if (res == CURLE_OK && httpCode == 200 && !code.empty()) {
                    sendMessage(replyTo, COLOR_GREEN + "✅ Found paste!" + COLOR_RESET);
                    sendMessage(replyTo, "Specify language and platforms: " + 
                               COLOR_YELLOW + "!compile <lang> <platforms>" + COLOR_RESET);
                    
                    // Store paste temporarily
                    // In real implementation, store with timeout
                    
                    curl_easy_cleanup(curl);
                    return;
                }
                
                curl_easy_cleanup(curl);
            }
        }
        
        sendMessage(replyTo, COLOR_RED + "❌ Could not fetch paste" + COLOR_RESET);
    }
};

// mIRC Script Generator for bot commands
class MircScriptGenerator {
public:
    static std::string generateBotScript() {
        return R"(
; BlackMamba mIRC Client Script
; Auto-compile from mIRC!

alias blackmamba {
  if (!$1) {
    echo -a 4Usage: /blackmamba <command>
    echo -a 3Commands: compile, status, download, help
    return
  }
  
  if ($1 == compile) {
    if (!$2) {
      echo -a 4Usage: /blackmamba compile <language> <code>
      return
    }
    
    ; Send compilation request
    msg BlackMamba !compile $2- 
  }
  elseif ($1 == status) {
    msg BlackMamba !status $2
  }
  elseif ($1 == download) {
    msg BlackMamba !download $2
  }
  elseif ($1 == help) {
    msg BlackMamba !compile help
  }
}

; Quick compile current script
alias compileself {
  var %file = $script
  var %code = $read(%file, 0)
  
  echo -a 3Compiling current script...
  msg BlackMamba !compile mirc on *:TEXT:*:*: { echo -s $nick said: $1- }
}

; Syntax highlighter for code
alias highlight {
  ; Add color codes to common keywords
  var %code = $1-
  %code = $replace(%code, if, 3if)
  %code = $replace(%code, else, 3else)
  %code = $replace(%code, while, 3while)
  %code = $replace(%code, for, 3for)
  %code = $replace(%code, return, 4return)
  
  echo -a %code
}

; Auto-installer for BlackMamba
on *:LOAD: {
  echo -a 4*** BlackMamba mIRC Integration Loaded! ***
  echo -a 3*** Type /blackmamba help for commands ***
  echo -a 3*** Join #blackmagii to use the bot ***
}
)";
    }
};

int main(int argc, char* argv[]) {
    std::cout << "🐍 BlackMamba IRC Bot - Remote Compilation Service" << std::endl;
    std::cout << "Powered by BlackMagii 🎩✨" << std::endl;
    
    // Check if generating mIRC script
    if (argc > 1 && std::string(argv[1]) == "--generate-mirc") {
        std::cout << "\nGenerating mIRC client script..." << std::endl;
        std::ofstream out("blackmamba_client.mrc");
        out << MircScriptGenerator::generateBotScript();
        out.close();
        std::cout << "✅ Created blackmamba_client.mrc" << std::endl;
        return 0;
    }
    
    // Load config if provided
    std::string configFile;
    if (argc > 1) {
        configFile = argv[1];
    }
    
    BlackMambaBot bot(configFile);
    bot.start();
    
    return 0;
}