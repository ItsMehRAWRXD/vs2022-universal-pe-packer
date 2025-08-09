#pragma once
#include "utils.h"
#include <string>
#include <vector>
#include <sstream>

// Custom HTTP client using only standard C++
class CustomHttpClient {
private:
    std::string lastError;
    
    // Socket operations (platform-specific)
    bool createSocket();
    bool connectToServer(const std::string& host, int port);
    bool sendData(const std::string& data);
    std::string receiveData();
    void closeSocket();
    
    // Platform-specific socket handle
    #ifdef _WIN32
        int sockfd;
    #else
        int sockfd;
    #endif
    
public:
    CustomHttpClient();
    ~CustomHttpClient();
    
    std::string post(const std::string& url, const std::string& data, const std::vector<std::string>& headers);
    std::string getLastError() const { return lastError; }
};

// ChatGPT API client class
class ChatGPTClient {
private:
    std::string apiKey;
    std::string apiUrl;
    std::vector<std::pair<std::string, std::string>> conversationHistory;
    CustomHttpClient httpClient;
    
    // JSON parsing helpers
    std::string extractResponseFromJson(const std::string& json);
    std::string createJsonPayload(const std::string& message);
    std::string escapeJsonString(const std::string& str);
    
public:
    ChatGPTClient();
    ~ChatGPTClient() = default;
    
    // Configuration
    bool setApiKey(const std::string& key);
    bool loadApiKeyFromFile(const std::string& filename);
    bool saveApiKeyToFile(const std::string& filename);
    
    // Chat functionality
    std::string sendMessage(const std::string& message);
    std::string sendCodeQuestion(const std::string& code, const std::string& question);
    std::string generateCode(const std::string& description, const std::string& language);
    std::string debugCode(const std::string& code, const std::string& error);
    
    // Conversation management
    void clearHistory();
    void addToHistory(const std::string& user, const std::string& assistant);
    std::vector<std::pair<std::string, std::string>> getHistory();
    
    // Utility functions
    bool isConfigured() const;
    std::string getLastError() const;
};

// ChatGPT integration tool
class ChatGPTTool : public BaseTool {
private:
    ChatGPTClient client;
    std::string lastResponse;
    
    void showChatMenu();
    void chatWithGPT();
    void askCodeQuestion();
    void generateCode();
    void debugCode();
    void configureAPI();
    void showHistory();
    void saveConversation();
    
public:
    ChatGPTTool();
    void run() override;
};