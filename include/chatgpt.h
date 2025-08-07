#pragma once
#include "utils.h"
#include <string>
#include <vector>
#include <curl/curl.h>

// ChatGPT API client class
class ChatGPTClient {
private:
    std::string apiKey;
    std::string apiUrl;
    std::vector<std::pair<std::string, std::string>> conversationHistory;
    
    // CURL callback function
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp);
    
    // HTTP request helper
    std::string makeHttpRequest(const std::string& url, const std::string& data, const std::string& contentType);
    
    // JSON parsing helpers
    std::string extractResponseFromJson(const std::string& json);
    std::string createJsonPayload(const std::string& message);
    
public:
    ChatGPTClient();
    ~ChatGPTClient();
    
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