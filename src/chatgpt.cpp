#include "chatgpt.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

// CURL callback function
size_t ChatGPTClient::WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

ChatGPTClient::ChatGPTClient() : apiUrl("https://api.openai.com/v1/chat/completions") {
    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

ChatGPTClient::~ChatGPTClient() {
    curl_global_cleanup();
}

bool ChatGPTClient::setApiKey(const std::string& key) {
    if (key.empty()) {
        return false;
    }
    apiKey = key;
    return true;
}

bool ChatGPTClient::loadApiKeyFromFile(const std::string& filename) {
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

bool ChatGPTClient::saveApiKeyToFile(const std::string& filename) {
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

std::string ChatGPTClient::makeHttpRequest(const std::string& url, const std::string& data, const std::string& contentType) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return "Error: Could not initialize CURL";
    }
    
    std::string response;
    
    // Set up headers
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, ("Content-Type: " + contentType).c_str());
    headers = curl_slist_append(headers, ("Authorization: Bearer " + apiKey).c_str());
    
    // Set up CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    // Clean up
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        return "Error: " + std::string(curl_easy_strerror(res));
    }
    
    return response;
}

std::string ChatGPTClient::createJsonPayload(const std::string& message) {
    std::stringstream ss;
    ss << "{";
    ss << "\"model\": \"gpt-3.5-turbo\",";
    ss << "\"messages\": [";
    ss << "{\"role\": \"user\", \"content\": \"" << message << "\"}";
    ss << "],";
    ss << "\"max_tokens\": 1000,";
    ss << "\"temperature\": 0.7";
    ss << "}";
    return ss.str();
}

std::string ChatGPTClient::extractResponseFromJson(const std::string& json) {
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

std::string ChatGPTClient::sendMessage(const std::string& message) {
    if (apiKey.empty()) {
        return "Error: API key not configured. Please set your OpenAI API key first.";
    }
    
    std::string payload = createJsonPayload(message);
    std::string response = makeHttpRequest(apiUrl, payload, "application/json");
    
    if (response.find("Error:") == 0) {
        return response;
    }
    
    std::string content = extractResponseFromJson(response);
    addToHistory(message, content);
    return content;
}

std::string ChatGPTClient::sendCodeQuestion(const std::string& code, const std::string& question) {
    std::string message = "Here's my code:\n```\n" + code + "\n```\n\nQuestion: " + question;
    return sendMessage(message);
}

std::string ChatGPTClient::generateCode(const std::string& description, const std::string& language) {
    std::string message = "Please generate " + language + " code for: " + description;
    return sendMessage(message);
}

std::string ChatGPTClient::debugCode(const std::string& code, const std::string& error) {
    std::string message = "I have this code:\n```\n" + code + "\n```\n\nAnd I'm getting this error:\n" + error + "\n\nCan you help me debug this?";
    return sendMessage(message);
}

void ChatGPTClient::clearHistory() {
    conversationHistory.clear();
}

void ChatGPTClient::addToHistory(const std::string& user, const std::string& assistant) {
    conversationHistory.push_back(std::make_pair(user, assistant));
}

std::vector<std::pair<std::string, std::string>> ChatGPTClient::getHistory() {
    return conversationHistory;
}

bool ChatGPTClient::isConfigured() const {
    return !apiKey.empty();
}

std::string ChatGPTClient::getLastError() const {
    return "No error information available";
}

// ChatGPT Tool Implementation
ChatGPTTool::ChatGPTTool() {
    // Try to load API key from file
    client.loadApiKeyFromFile("chatgpt_api_key.txt");
}

void ChatGPTTool::run() {
    while (true) {
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

void ChatGPTTool::chatWithGPT() {
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

void ChatGPTTool::askCodeQuestion() {
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

void ChatGPTTool::generateCode() {
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

void ChatGPTTool::debugCode() {
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

void ChatGPTTool::configureAPI() {
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

void ChatGPTTool::showHistory() {
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

void ChatGPTTool::saveConversation() {
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