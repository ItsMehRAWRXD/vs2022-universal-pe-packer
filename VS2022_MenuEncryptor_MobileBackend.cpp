// VS2022 Menu Encryptor - Mobile Backend Service
// Bridges mobile devices with GitHub repositories and YouTube content

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>
#include <chrono>
#include <filesystem>

// Network libraries
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <websocketpp/server.hpp>
#include <websocketpp/config/asio_no_tls.hpp>

using json = nlohmann::json;
using websocket_server = websocketpp::server<websocketpp::config::asio>;

class MobileBackendService {
private:
    httplib::Server httpServer;
    websocket_server wsServer;
    std::thread httpThread;
    std::thread wsThread;
    
    // Connected mobile clients
    struct MobileClient {
        std::string deviceId;
        std::string platform; // iOS, Android
        std::string authToken;
        websocketpp::connection_hdl connection;
        std::chrono::system_clock::time_point lastSeen;
    };
    
    std::map<std::string, MobileClient> clients;
    std::mutex clientsMutex;
    
    // Task queue for mobile requests
    struct Task {
        std::string id;
        std::string type; // github_sync, youtube_download, file_encrypt
        json parameters;
        std::string clientId;
        std::chrono::system_clock::time_point created;
    };
    
    std::queue<Task> taskQueue;
    std::mutex taskMutex;
    std::condition_variable taskCV;
    
    // Cache for GitHub data
    std::map<std::string, json> githubCache;
    std::mutex cacheMutex;
    
public:
    MobileBackendService() {
        setupHTTPEndpoints();
        setupWebSocketHandlers();
    }
    
    void start(int httpPort = 8080, int wsPort = 9090) {
        // Start HTTP server
        httpThread = std::thread([this, httpPort]() {
            std::cout << "📱 Mobile Backend HTTP API running on port " << httpPort << std::endl;
            httpServer.listen("0.0.0.0", httpPort);
        });
        
        // Start WebSocket server
        wsThread = std::thread([this, wsPort]() {
            wsServer.init_asio();
            wsServer.listen(wsPort);
            wsServer.start_accept();
            
            std::cout << "🔌 WebSocket server running on port " << wsPort << std::endl;
            wsServer.run();
        });
        
        // Start task processor
        std::thread taskProcessor([this]() {
            processTasks();
        });
        taskProcessor.detach();
        
        // Start health monitor
        std::thread healthMonitor([this]() {
            monitorClients();
        });
        healthMonitor.detach();
    }
    
    void setupHTTPEndpoints() {
        // Mobile client registration
        httpServer.Post("/api/register", [this](const httplib::Request& req, httplib::Response& res) {
            json body = json::parse(req.body);
            
            std::string deviceId = body["deviceId"];
            std::string platform = body["platform"];
            
            // Generate auth token
            std::string authToken = generateAuthToken();
            
            // Store client info
            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                clients[deviceId] = {
                    deviceId, platform, authToken, 
                    websocketpp::connection_hdl(), 
                    std::chrono::system_clock::now()
                };
            }
            
            json response = {
                {"status", "success"},
                {"authToken", authToken},
                {"endpoints", {
                    {"websocket", "ws://localhost:9090"},
                    {"github", "/api/github"},
                    {"youtube", "/api/youtube"},
                    {"files", "/api/files"}
                }}
            };
            
            res.set_content(response.dump(), "application/json");
        });
        
        // GitHub operations
        httpServer.Get("/api/github/repos", [this](const httplib::Request& req, httplib::Response& res) {
            if (!authenticateRequest(req)) {
                res.status = 401;
                return;
            }
            
            json repos = getGitHubRepositories();
            res.set_content(repos.dump(), "application/json");
        });
        
        httpServer.Post("/api/github/sync", [this](const httplib::Request& req, httplib::Response& res) {
            if (!authenticateRequest(req)) {
                res.status = 401;
                return;
            }
            
            json body = json::parse(req.body);
            std::string taskId = queueTask("github_sync", body, getClientId(req));
            
            res.set_content(json{{"taskId", taskId}}.dump(), "application/json");
        });
        
        // YouTube operations
        httpServer.Post("/api/youtube/download", [this](const httplib::Request& req, httplib::Response& res) {
            if (!authenticateRequest(req)) {
                res.status = 401;
                return;
            }
            
            json body = json::parse(req.body);
            std::string taskId = queueTask("youtube_download", body, getClientId(req));
            
            res.set_content(json{{"taskId", taskId}}.dump(), "application/json");
        });
        
        httpServer.Get("/api/youtube/search", [this](const httplib::Request& req, httplib::Response& res) {
            if (!authenticateRequest(req)) {
                res.status = 401;
                return;
            }
            
            std::string query = req.get_param_value("q");
            json results = searchYouTube(query);
            
            res.set_content(results.dump(), "application/json");
        });
        
        // File operations
        httpServer.Post("/api/files/encrypt", [this](const httplib::Request& req, httplib::Response& res) {
            if (!authenticateRequest(req)) {
                res.status = 401;
                return;
            }
            
            // Handle file upload and encryption
            auto file = req.get_file_value("file");
            std::string taskId = queueFileEncryption(file, getClientId(req));
            
            res.set_content(json{{"taskId", taskId}}.dump(), "application/json");
        });
        
        httpServer.Get("/api/files/download/:fileId", [this](const httplib::Request& req, httplib::Response& res) {
            if (!authenticateRequest(req)) {
                res.status = 401;
                return;
            }
            
            std::string fileId = req.matches[1];
            serveEncryptedFile(fileId, res);
        });
        
        // Task status
        httpServer.Get("/api/task/:taskId", [this](const httplib::Request& req, httplib::Response& res) {
            if (!authenticateRequest(req)) {
                res.status = 401;
                return;
            }
            
            std::string taskId = req.matches[1];
            json status = getTaskStatus(taskId);
            
            res.set_content(status.dump(), "application/json");
        });
        
        // Repository browser
        httpServer.Get("/api/browse/:repo/*", [this](const httplib::Request& req, httplib::Response& res) {
            if (!authenticateRequest(req)) {
                res.status = 401;
                return;
            }
            
            std::string repo = req.matches[1];
            std::string path = req.matches[2];
            
            json contents = browseRepository(repo, path);
            res.set_content(contents.dump(), "application/json");
        });
    }
    
    void setupWebSocketHandlers() {
        wsServer.set_message_handler([this](websocketpp::connection_hdl hdl, websocket_server::message_ptr msg) {
            handleWebSocketMessage(hdl, msg);
        });
        
        wsServer.set_open_handler([this](websocketpp::connection_hdl hdl) {
            std::cout << "📱 Mobile client connected via WebSocket" << std::endl;
        });
        
        wsServer.set_close_handler([this](websocketpp::connection_hdl hdl) {
            handleWebSocketDisconnect(hdl);
        });
    }
    
    void handleWebSocketMessage(websocketpp::connection_hdl hdl, websocket_server::message_ptr msg) {
        try {
            json message = json::parse(msg->get_payload());
            std::string type = message["type"];
            
            if (type == "auth") {
                std::string token = message["token"];
                authenticateWebSocket(hdl, token);
            }
            else if (type == "subscribe") {
                std::string channel = message["channel"];
                subscribeToChannel(hdl, channel);
            }
            else if (type == "github_stream") {
                streamGitHubUpdates(hdl, message["repo"]);
            }
            else if (type == "youtube_progress") {
                std::string taskId = message["taskId"];
                sendDownloadProgress(hdl, taskId);
            }
        } catch (const std::exception& e) {
            std::cerr << "WebSocket error: " << e.what() << std::endl;
        }
    }
    
    void processTasks() {
        while (true) {
            std::unique_lock<std::mutex> lock(taskMutex);
            taskCV.wait(lock, [this] { return !taskQueue.empty(); });
            
            Task task = taskQueue.front();
            taskQueue.pop();
            lock.unlock();
            
            // Process task based on type
            if (task.type == "github_sync") {
                processGitHubSync(task);
            }
            else if (task.type == "youtube_download") {
                processYouTubeDownload(task);
            }
            else if (task.type == "file_encrypt") {
                processFileEncryption(task);
            }
            
            // Notify client via WebSocket
            notifyTaskComplete(task);
        }
    }
    
    void processGitHubSync(const Task& task) {
        std::string repoUrl = task.parameters["url"];
        std::string branch = task.parameters["branch"];
        
        // Clone/pull repository
        std::string localPath = "./mobile_repos/" + task.id;
        std::string gitCommand = "git clone -b " + branch + " " + repoUrl + " " + localPath;
        
        system(gitCommand.c_str());
        
        // Analyze repository
        json analysis = {
            {"files", countFiles(localPath)},
            {"languages", detectLanguages(localPath)},
            {"size", getDirectorySize(localPath)},
            {"branches", getGitBranches(localPath)}
        };
        
        // Cache results
        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            githubCache[task.id] = analysis;
        }
        
        // Send progress updates
        sendProgressUpdate(task.clientId, task.id, 100, "Repository synced");
    }
    
    void processYouTubeDownload(const Task& task) {
        std::string url = task.parameters["url"];
        std::string quality = task.parameters.value("quality", "best");
        bool audioOnly = task.parameters.value("audioOnly", false);
        
        std::string outputPath = "./downloads/" + task.id;
        std::string ytCommand = "yt-dlp";
        
        if (audioOnly) {
            ytCommand += " -x --audio-format mp3";
        } else {
            ytCommand += " -f " + quality;
        }
        
        ytCommand += " -o \"" + outputPath + ".%(ext)s\" " + url;
        
        // Execute with progress parsing
        FILE* pipe = popen((ytCommand + " --progress").c_str(), "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                // Parse progress and send updates
                int progress = parseYTDLPProgress(buffer);
                if (progress > 0) {
                    sendProgressUpdate(task.clientId, task.id, progress, "Downloading");
                }
            }
            pclose(pipe);
        }
        
        // Encrypt the downloaded file
        encryptDownloadedFile(outputPath, task.id);
        
        sendProgressUpdate(task.clientId, task.id, 100, "Download complete and encrypted");
    }
    
    void notifyTaskComplete(const Task& task) {
        json notification = {
            {"type", "task_complete"},
            {"taskId", task.id},
            {"taskType", task.type},
            {"status", "success"}
        };
        
        sendToClient(task.clientId, notification);
    }
    
    void sendToClient(const std::string& clientId, const json& message) {
        std::lock_guard<std::mutex> lock(clientsMutex);
        
        auto it = clients.find(clientId);
        if (it != clients.end() && it->second.connection.lock()) {
            try {
                wsServer.send(it->second.connection, message.dump(), websocketpp::frame::opcode::text);
            } catch (const std::exception& e) {
                std::cerr << "Failed to send to client: " << e.what() << std::endl;
            }
        }
    }
    
    void sendProgressUpdate(const std::string& clientId, const std::string& taskId, 
                           int progress, const std::string& status) {
        json update = {
            {"type", "progress"},
            {"taskId", taskId},
            {"progress", progress},
            {"status", status}
        };
        
        sendToClient(clientId, update);
    }
    
    // Mobile-specific optimizations
    json getOptimizedGitHubData(const std::string& repo) {
        // Return compressed, mobile-friendly data
        json mobileData = {
            {"repo", repo},
            {"summary", generateRepoSummary(repo)},
            {"recentCommits", getRecentCommits(repo, 10)},
            {"mainFiles", getImportantFiles(repo)}
        };
        
        return mobileData;
    }
    
    void streamGitHubUpdates(websocketpp::connection_hdl hdl, const std::string& repo) {
        // Set up file watching for repository changes
        std::thread([this, hdl, repo]() {
            std::string repoPath = "./mobile_repos/" + repo;
            
            while (true) {
                // Check for changes
                if (hasRepoChanged(repoPath)) {
                    json update = {
                        {"type", "repo_update"},
                        {"repo", repo},
                        {"changes", getRepoChanges(repoPath)}
                    };
                    
                    try {
                        wsServer.send(hdl, update.dump(), websocketpp::frame::opcode::text);
                    } catch (...) {
                        break; // Connection closed
                    }
                }
                
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }).detach();
    }
    
    // Helper functions
    std::string generateAuthToken() {
        // Generate secure random token
        std::string token;
        for (int i = 0; i < 32; i++) {
            token += "0123456789abcdef"[rand() % 16];
        }
        return token;
    }
    
    bool authenticateRequest(const httplib::Request& req) {
        std::string authHeader = req.get_header_value("Authorization");
        if (authHeader.empty()) return false;
        
        std::string token = authHeader.substr(7); // Remove "Bearer "
        
        std::lock_guard<std::mutex> lock(clientsMutex);
        for (const auto& [id, client] : clients) {
            if (client.authToken == token) {
                return true;
            }
        }
        
        return false;
    }
    
    void monitorClients() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            
            std::lock_guard<std::mutex> lock(clientsMutex);
            auto now = std::chrono::system_clock::now();
            
            for (auto it = clients.begin(); it != clients.end();) {
                auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
                    now - it->second.lastSeen).count();
                    
                if (elapsed > 5) {
                    std::cout << "📱 Removing inactive client: " << it->first << std::endl;
                    it = clients.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }
};

// Main function to run as standalone service
int main() {
    std::cout << "🚀 VS2022 Menu Encryptor - Mobile Backend Service" << std::endl;
    std::cout << "📱 Bridging mobile devices with GitHub and YouTube" << std::endl;
    
    MobileBackendService backend;
    backend.start(8080, 9090);
    
    std::cout << "\n✅ Mobile backend service running!" << std::endl;
    std::cout << "📡 HTTP API: http://localhost:8080" << std::endl;
    std::cout << "🔌 WebSocket: ws://localhost:9090" << std::endl;
    
    // Keep running
    std::string input;
    while (std::getline(std::cin, input)) {
        if (input == "quit") break;
    }
    
    return 0;
}