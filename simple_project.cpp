#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <cctype>
#include <limits>
#include <sstream>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// Base class for all tools
class BaseTool {
public:
    virtual ~BaseTool() = default;
    virtual void run() = 0;
};

// String utility functions
std::string toUpperCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

std::string toLowerCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string reverseString(const std::string& str) {
    std::string result = str;
    std::reverse(result.begin(), result.end());
    return result;
}

std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

// Input validation functions
bool isValidNumber(const std::string& str) {
    std::istringstream iss(str);
    double d;
    iss >> std::noskipws >> d;
    return iss.eof() && !iss.fail();
}

int getValidInt(const std::string& prompt) {
    int value;
    while (true) {
        std::cout << prompt;
        std::string input;
        std::getline(std::cin, input);
        
        std::istringstream iss(input);
        if (iss >> value) {
            return value;
        }
        std::cout << "Invalid input. Please enter a valid number." << std::endl;
    }
}

double getValidDouble(const std::string& prompt) {
    double value;
    while (true) {
        std::cout << prompt;
        std::string input;
        std::getline(std::cin, input);
        
        std::istringstream iss(input);
        if (iss >> value) {
            return value;
        }
        std::cout << "Invalid input. Please enter a valid number." << std::endl;
    }
}

// Display utilities
void clearScreen() {
    system("cls");
}

void pauseScreen() {
    std::cout << "\nPress Enter to continue...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void printHeader(const std::string& title) {
    std::cout << std::string(title.length() + 4, '=') << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << std::string(title.length() + 4, '=') << std::endl;
}

void printSeparator(char ch = '-', int length = 50) {
    std::cout << std::string(length, ch) << std::endl;
}

// Custom HTTP client using only standard C++
class CustomHttpClient {
private:
    std::string lastError;
    int sockfd;
    
    bool createSocket() {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            lastError = "Failed to create socket";
            return false;
        }
        return true;
    }
    
    bool connectToServer(const std::string& host, int port) {
        struct sockaddr_in serverAddr;
        struct hostent* server;
        
        server = gethostbyname(host.c_str());
        if (server == NULL) {
            lastError = "No such host";
            return false;
        }
        
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        memcpy(&serverAddr.sin_addr.s_addr, server->h_addr, server->h_length);
        serverAddr.sin_port = htons(port);
        
        if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            lastError = "Connection failed";
            return false;
        }
        
        return true;
    }
    
    bool sendData(const std::string& data) {
        int bytesSent = send(sockfd, data.c_str(), data.length(), 0);
        if (bytesSent < 0) {
            lastError = "Failed to send data";
            return false;
        }
        return true;
    }
    
    std::string receiveData() {
        std::string response;
        char buffer[4096];
        
        while (true) {
            int bytesReceived = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytesReceived <= 0) {
                break;
            }
            buffer[bytesReceived] = '\0';
            response += buffer;
        }
        
        return response;
    }
    
    void closeSocket() {
        if (sockfd >= 0) {
            closesocket(sockfd);
            sockfd = -1;
        }
    }
    
public:
    CustomHttpClient() : sockfd(-1) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }
    
    ~CustomHttpClient() {
        closeSocket();
        WSACleanup();
    }
    
    std::string post(const std::string& url, const std::string& data, const std::vector<std::string>& headers) {
        // Parse URL
        std::string protocol, host, path;
        size_t protocolEnd = url.find("://");
        if (protocolEnd != std::string::npos) {
            protocol = url.substr(0, protocolEnd);
            size_t hostStart = protocolEnd + 3;
            size_t hostEnd = url.find("/", hostStart);
            if (hostEnd != std::string::npos) {
                host = url.substr(hostStart, hostEnd - hostStart);
                path = url.substr(hostEnd);
            } else {
                host = url.substr(hostStart);
                path = "/";
            }
        } else {
            lastError = "Invalid URL format";
            return "";
        }
        
        // Default to HTTPS port
        int port = 443;
        if (protocol == "http") {
            port = 80;
        }
        
        // Create socket and connect
        if (!createSocket()) {
            return "Error: " + lastError;
        }
        
        if (!connectToServer(host, port)) {
            closeSocket();
            return "Error: " + lastError;
        }
        
        // Build HTTP request
        std::stringstream request;
        request << "POST " << path << " HTTP/1.1\r\n";
        request << "Host: " << host << "\r\n";
        request << "Content-Type: application/json\r\n";
        request << "Content-Length: " << data.length() << "\r\n";
        
        // Add custom headers
        for (const auto& header : headers) {
            request << header << "\r\n";
        }
        
        request << "\r\n";
        request << data;
        
        // Send request
        if (!sendData(request.str())) {
            closeSocket();
            return "Error: " + lastError;
        }
        
        // Receive response
        std::string response = receiveData();
        closeSocket();
        
        // Extract body from HTTP response
        size_t bodyStart = response.find("\r\n\r\n");
        if (bodyStart != std::string::npos) {
            return response.substr(bodyStart + 4);
        }
        
        return response;
    }
    
    std::string getLastError() const { return lastError; }
};

// ChatGPT API client class
class ChatGPTClient {
private:
    std::string apiKey;
    std::string apiUrl;
    std::vector<std::pair<std::string, std::string>> conversationHistory;
    CustomHttpClient httpClient;
    
    std::string escapeJsonString(const std::string& str) {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c; break;
            }
        }
        return result;
    }
    
    std::string createJsonPayload(const std::string& message) {
        std::stringstream ss;
        ss << "{";
        ss << "\"model\": \"gpt-3.5-turbo\",";
        ss << "\"messages\": [";
        ss << "{\"role\": \"user\", \"content\": \"" << escapeJsonString(message) << "\"}";
        ss << "],";
        ss << "\"max_tokens\": 1000,";
        ss << "\"temperature\": 0.7";
        ss << "}";
        return ss.str();
    }
    
    std::string extractResponseFromJson(const std::string& json) {
        // Simple JSON parsing - look for "content" field
        size_t contentPos = json.find("\"content\":");
        if (contentPos == std::string::npos) {
            return "Error: Could not parse response";
        }
        
        // Find the start of the content
        size_t startPos = json.find("\"", contentPos + 10);
        if (startPos == std::string::npos) {
            return "Error: Could not parse response";
        }
        startPos++;
        
        // Find the end of the content
        size_t endPos = json.find("\"", startPos);
        if (endPos == std::string::npos) {
            return "Error: Could not parse response";
        }
        
        std::string content = json.substr(startPos, endPos - startPos);
        
        // Unescape common characters
        size_t pos = 0;
        while ((pos = content.find("\\n", pos)) != std::string::npos) {
            content.replace(pos, 2, "\n");
            pos++;
        }
        
        pos = 0;
        while ((pos = content.find("\\t", pos)) != std::string::npos) {
            content.replace(pos, 2, "\t");
            pos++;
        }
        
        return content;
    }
    
public:
    ChatGPTClient() : apiUrl("https://api.openai.com/v1/chat/completions") {
    }
    
    bool setApiKey(const std::string& key) {
        if (key.empty()) {
            return false;
        }
        apiKey = key;
        return true;
    }
    
    bool loadApiKeyFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        
        std::string key;
        std::getline(file, key);
        file.close();
        
        // Remove whitespace
        key.erase(0, key.find_first_not_of(" \t\r\n"));
        key.erase(key.find_last_not_of(" \t\r\n") + 1);
        
        return setApiKey(key);
    }
    
    bool saveApiKeyToFile(const std::string& filename) {
        if (apiKey.empty()) {
            return false;
        }
        
        std::ofstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        
        file << apiKey << std::endl;
        file.close();
        return true;
    }
    
    std::string sendMessage(const std::string& message) {
        if (apiKey.empty()) {
            return "Error: API key not configured. Please set your OpenAI API key first.";
        }
        
        std::string payload = createJsonPayload(message);
        std::vector<std::string> headers = {
            "Authorization: Bearer " + apiKey
        };
        
        std::string response = httpClient.post(apiUrl, payload, headers);
        
        if (response.find("Error:") == 0) {
            return response;
        }
        
        std::string content = extractResponseFromJson(response);
        addToHistory(message, content);
        return content;
    }
    
    std::string sendCodeQuestion(const std::string& code, const std::string& question) {
        std::string message = "Here's my code:\n```\n" + code + "\n```\n\nQuestion: " + question;
        return sendMessage(message);
    }
    
    std::string generateCode(const std::string& description, const std::string& language) {
        std::string message = "Please generate " + language + " code for: " + description;
        return sendMessage(message);
    }
    
    std::string debugCode(const std::string& code, const std::string& error) {
        std::string message = "I have this code:\n```\n" + code + "\n```\n\nAnd I'm getting this error:\n" + error + "\n\nCan you help me debug this?";
        return sendMessage(message);
    }
    
    void clearHistory() {
        conversationHistory.clear();
    }
    
    void addToHistory(const std::string& user, const std::string& assistant) {
        conversationHistory.push_back(std::make_pair(user, assistant));
    }
    
    std::vector<std::pair<std::string, std::string>> getHistory() {
        return conversationHistory;
    }
    
    bool isConfigured() const {
        return !apiKey.empty();
    }
    
    std::string getLastError() const {
        return httpClient.getLastError();
    }
};

// ChatGPT integration tool
class ChatGPTTool : public BaseTool {
private:
    ChatGPTClient client;
    std::string lastResponse;
    
    void showChatMenu() {
        clearScreen();
        printHeader("ChatGPT Integration");
        
        if (!client.isConfigured()) {
            std::cout << "Warning: API key not configured!" << std::endl;
            std::cout << "Please configure your OpenAI API key first.\n" << std::endl;
        }
        
        std::cout << "1. Chat with ChatGPT" << std::endl;
        std::cout << "2. Ask Code Question" << std::endl;
        std::cout << "3. Generate Code" << std::endl;
        std::cout << "4. Debug Code" << std::endl;
        std::cout << "5. Configure API Key" << std::endl;
        std::cout << "6. View Chat History" << std::endl;
        std::cout << "7. Save Conversation" << std::endl;
        std::cout << "8. Back to Main Menu" << std::endl;
    }
    
    void chatWithGPT() {
        printHeader("Chat with ChatGPT");
        
        if (!client.isConfigured()) {
            std::cout << "Please configure your API key first!" << std::endl;
            return;
        }
        
        std::cout << "Enter your message (type 'quit' to exit):" << std::endl;
        
        while (true) {
            std::string message;
            std::cout << "\nYou: ";
            std::cin.ignore();
            std::getline(std::cin, message);
            
            if (message == "quit" || message == "exit") {
                break;
            }
            
            if (message.empty()) {
                continue;
            }
            
            std::cout << "\nChatGPT: ";
            std::cout << "Thinking..." << std::endl;
            
            lastResponse = client.sendMessage(message);
            std::cout << lastResponse << std::endl;
        }
    }
    
    void askCodeQuestion() {
        printHeader("Ask Code Question");
        
        if (!client.isConfigured()) {
            std::cout << "Please configure your API key first!" << std::endl;
            return;
        }
        
        std::string code;
        std::cout << "Enter your code (type 'END' on a new line to finish):" << std::endl;
        std::cin.ignore();
        
        std::string line;
        while (std::getline(std::cin, line) && line != "END") {
            code += line + "\n";
        }
        
        std::string question;
        std::cout << "Enter your question: ";
        std::getline(std::cin, question);
        
        std::cout << "\nChatGPT: ";
        std::cout << "Analyzing your code..." << std::endl;
        
        lastResponse = client.sendCodeQuestion(code, question);
        std::cout << lastResponse << std::endl;
    }
    
    void generateCode() {
        printHeader("Generate Code");
        
        if (!client.isConfigured()) {
            std::cout << "Please configure your API key first!" << std::endl;
            return;
        }
        
        std::string description;
        std::cout << "Describe what you want to build: ";
        std::cin.ignore();
        std::getline(std::cin, description);
        
        std::cout << "Choose language (cpp, python, javascript, etc.): ";
        std::string language;
        std::getline(std::cin, language);
        
        std::cout << "\nChatGPT: ";
        std::cout << "Generating code..." << std::endl;
        
        lastResponse = client.generateCode(description, language);
        std::cout << lastResponse << std::endl;
    }
    
    void debugCode() {
        printHeader("Debug Code");
        
        if (!client.isConfigured()) {
            std::cout << "Please configure your API key first!" << std::endl;
            return;
        }
        
        std::string code;
        std::cout << "Enter your code (type 'END' on a new line to finish):" << std::endl;
        std::cin.ignore();
        
        std::string line;
        while (std::getline(std::cin, line) && line != "END") {
            code += line + "\n";
        }
        
        std::string error;
        std::cout << "Enter the error message: ";
        std::getline(std::cin, error);
        
        std::cout << "\nChatGPT: ";
        std::cout << "Analyzing error..." << std::endl;
        
        lastResponse = client.debugCode(code, error);
        std::cout << lastResponse << std::endl;
    }
    
    void configureAPI() {
        printHeader("Configure API Key");
        
        std::cout << "Enter your OpenAI API key: ";
        std::string apiKey;
        std::cin.ignore();
        std::getline(std::cin, apiKey);
        
        if (client.setApiKey(apiKey)) {
            std::cout << "API key configured successfully!" << std::endl;
            
            std::cout << "Save API key to file? (y/n): ";
            char choice;
            std::cin >> choice;
            
            if (choice == 'y' || choice == 'Y') {
                if (client.saveApiKeyToFile("chatgpt_api_key.txt")) {
                    std::cout << "API key saved to chatgpt_api_key.txt" << std::endl;
                } else {
                    std::cout << "Failed to save API key!" << std::endl;
                }
            }
        } else {
            std::cout << "Invalid API key!" << std::endl;
        }
    }
    
    void showHistory() {
        printHeader("Chat History");
        
        auto history = client.getHistory();
        if (history.empty()) {
            std::cout << "No chat history available." << std::endl;
            return;
        }
        
        for (size_t i = 0; i < history.size(); ++i) {
            std::cout << "--- Conversation " << (i + 1) << " ---" << std::endl;
            std::cout << "You: " << history[i].first << std::endl;
            std::cout << "ChatGPT: " << history[i].second << std::endl;
            std::cout << std::endl;
        }
    }
    
    void saveConversation() {
        printHeader("Save Conversation");
        
        auto history = client.getHistory();
        if (history.empty()) {
            std::cout << "No conversation to save." << std::endl;
            return;
        }
        
        std::string filename;
        std::cout << "Enter filename to save conversation: ";
        std::cin.ignore();
        std::getline(std::cin, filename);
        
        if (filename.empty()) {
            filename = "chatgpt_conversation.txt";
        }
        
        std::ofstream file(filename);
        if (file.is_open()) {
            file << "ChatGPT Conversation Log" << std::endl;
            file << "========================" << std::endl << std::endl;
            
            for (size_t i = 0; i < history.size(); ++i) {
                file << "--- Conversation " << (i + 1) << " ---" << std::endl;
                file << "You: " << history[i].first << std::endl;
                file << "ChatGPT: " << history[i].second << std::endl;
                file << std::endl;
            }
            
            file.close();
            std::cout << "Conversation saved to " << filename << std::endl;
        } else {
            std::cout << "Failed to save conversation!" << std::endl;
        }
    }
    
public:
    ChatGPTTool() {
        // Try to load API key from file
        client.loadApiKeyFromFile("chatgpt_api_key.txt");
    }
    
    void run() override {
        while (true) {
            showChatMenu();
            
            int choice = getValidInt("Choose an option: ");
            
            switch (choice) {
                case 1:
                    chatWithGPT();
                    break;
                case 2:
                    askCodeQuestion();
                    break;
                case 3:
                    generateCode();
                    break;
                case 4:
                    debugCode();
                    break;
                case 5:
                    configureAPI();
                    break;
                case 6:
                    showHistory();
                    break;
                case 7:
                    saveConversation();
                    break;
                case 8:
                    return;
                default:
                    std::cout << "Invalid option!" << std::endl;
            }
            pauseScreen();
        }
    }
};

class AIEnvironment {
private:
    std::vector<std::unique_ptr<BaseTool>> tools;
    
public:
    AIEnvironment() {
        // Initialize tools
        tools.push_back(std::make_unique<ChatGPTTool>());
    }
    
    void showMenu() {
        std::cout << "\n=== C++ AI Development Environment ===" << std::endl;
        std::cout << "1. ChatGPT Integration" << std::endl;
        std::cout << "2. Exit" << std::endl;
        std::cout << "Choose an option: ";
    }
    
    void run() {
        while (true) {
            showMenu();
            int choice;
            std::cin >> choice;
            
            switch (choice) {
                case 1:
                    tools[0]->run();
                    break;
                case 2:
                    std::cout << "Goodbye!" << std::endl;
                    return;
                default:
                    std::cout << "Invalid option. Please try again." << std::endl;
            }
        }
    }
};

int main() {
    std::cout << "Starting C++ AI Development Environment..." << std::endl;
    
    AIEnvironment env;
    env.run();
    
    return 0;
}