// Mobile Compiler Service - Part of VS2022 Menu Encryptor Suite
// Provides compilation capabilities for mobile devices via online services and custom backend

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <thread>
#include <mutex>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

// Network libraries
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <curl/curl.h>

using json = nlohmann::json;
namespace fs = std::filesystem;

class MobileCompilerService {
private:
    struct CompilerProvider {
        std::string name;
        std::string apiUrl;
        std::string apiKey;
        std::vector<std::string> supportedLanguages;
        bool requiresAuth;
        int rateLimit; // requests per minute
    };
    
    struct CompilationRequest {
        std::string id;
        std::string language;
        std::string code;
        std::string input;
        std::string compilerFlags;
        std::string userId;
        std::chrono::system_clock::time_point timestamp;
        std::string provider; // which compiler to use
    };
    
    struct CompilationResult {
        std::string id;
        std::string output;
        std::string errors;
        int exitCode;
        double executionTime;
        size_t memoryUsed;
        std::string assemblyOutput;
        std::string provider;
    };
    
    // Online compiler providers
    std::map<std::string, CompilerProvider> providers;
    
    // Request queue
    std::queue<CompilationRequest> requestQueue;
    std::mutex queueMutex;
    std::condition_variable queueCV;
    
    // Results cache
    std::map<std::string, CompilationResult> resultsCache;
    std::mutex cacheMutex;
    
    // HTTP server for mobile clients
    httplib::Server server;
    
    // Rate limiting
    std::map<std::string, int> userRequestCount;
    std::mutex rateLimitMutex;
    
    // Local compilation sandbox (for our own backend)
    std::string sandboxPath = "./compilation_sandbox/";
    
public:
    MobileCompilerService() {
        initializeProviders();
        setupEndpoints();
        createSandboxEnvironment();
    }
    
    void initializeProviders() {
        // Godbolt Compiler Explorer
        providers["godbolt"] = {
            "Godbolt Compiler Explorer",
            "https://godbolt.org/api/",
            "", // No API key required
            {"c++", "c", "rust", "go", "python", "java", "csharp", "swift", "kotlin"},
            false,
            60
        };
        
        // JDoodle API
        providers["jdoodle"] = {
            "JDoodle Online Compiler",
            "https://api.jdoodle.com/v1/execute",
            "YOUR_JDOODLE_API_KEY", // Replace with actual key
            {"cpp17", "c", "python3", "java", "nodejs", "csharp", "php", "ruby", "go", "rust"},
            true,
            200
        };
        
        // Wandbox
        providers["wandbox"] = {
            "Wandbox Online Compiler",
            "https://wandbox.org/api/",
            "", // No API key required
            {"gcc-head", "clang-head", "python", "ruby", "rust", "go", "java"},
            false,
            30
        };
        
        // Judge0 API
        providers["judge0"] = {
            "Judge0 Compiler API",
            "https://judge0-ce.p.rapidapi.com/",
            "YOUR_JUDGE0_API_KEY", // Replace with actual key
            {"cpp", "c", "python", "java", "javascript", "rust", "go", "ruby", "csharp"},
            true,
            100
        };
        
        // Our custom backend
        providers["custom"] = {
            "VS2022 Custom Compiler",
            "local://",
            "",
            {"c++", "c", "python", "javascript", "assembly", "rust", "go"},
            false,
            1000 // Higher limit for our own service
        };
    }
    
    void setupEndpoints() {
        // Submit compilation request
        server.Post("/api/compile", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                json request = json::parse(req.body);
                
                CompilationRequest compReq;
                compReq.id = generateRequestId();
                compReq.language = request["language"];
                compReq.code = request["code"];
                compReq.input = request.value("input", "");
                compReq.compilerFlags = request.value("flags", "");
                compReq.userId = request.value("userId", "anonymous");
                compReq.provider = request.value("provider", "auto");
                compReq.timestamp = std::chrono::system_clock::now();
                
                // Check rate limit
                if (!checkRateLimit(compReq.userId)) {
                    res.status = 429;
                    res.set_content(json{{"error", "Rate limit exceeded"}}.dump(), "application/json");
                    return;
                }
                
                // Queue the request
                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    requestQueue.push(compReq);
                }
                queueCV.notify_one();
                
                json response = {
                    {"requestId", compReq.id},
                    {"status", "queued"},
                    {"estimatedTime", estimateCompilationTime(compReq.language)}
                };
                
                res.set_content(response.dump(), "application/json");
                
            } catch (const std::exception& e) {
                res.status = 400;
                res.set_content(json{{"error", e.what()}}.dump(), "application/json");
            }
        });
        
        // Get compilation result
        server.Get("/api/compile/:requestId", [this](const httplib::Request& req, httplib::Response& res) {
            std::string requestId = req.matches[1];
            
            std::lock_guard<std::mutex> lock(cacheMutex);
            auto it = resultsCache.find(requestId);
            
            if (it != resultsCache.end()) {
                json response = {
                    {"requestId", it->second.id},
                    {"status", "completed"},
                    {"output", it->second.output},
                    {"errors", it->second.errors},
                    {"exitCode", it->second.exitCode},
                    {"executionTime", it->second.executionTime},
                    {"memoryUsed", it->second.memoryUsed},
                    {"assembly", it->second.assemblyOutput},
                    {"provider", it->second.provider}
                };
                
                res.set_content(response.dump(), "application/json");
            } else {
                res.set_content(json{{"status", "pending"}}.dump(), "application/json");
            }
        });
        
        // List available compilers
        server.Get("/api/compilers", [this](const httplib::Request& req, httplib::Response& res) {
            json compilers = json::array();
            
            for (const auto& [name, provider] : providers) {
                compilers.push_back({
                    {"name", name},
                    {"displayName", provider.name},
                    {"languages", provider.supportedLanguages},
                    {"requiresAuth", provider.requiresAuth},
                    {"rateLimit", provider.rateLimit}
                });
            }
            
            res.set_content(compilers.dump(), "application/json");
        });
        
        // Get compiler options for a language
        server.Get("/api/compiler-options/:language", [this](const httplib::Request& req, httplib::Response& res) {
            std::string language = req.matches[1];
            
            json options = getCompilerOptions(language);
            res.set_content(options.dump(), "application/json");
        });
        
        // Submit batch compilation
        server.Post("/api/compile/batch", [this](const httplib::Request& req, httplib::Response& res) {
            json request = json::parse(req.body);
            json response = json::array();
            
            for (const auto& item : request["requests"]) {
                CompilationRequest compReq;
                compReq.id = generateRequestId();
                compReq.language = item["language"];
                compReq.code = item["code"];
                compReq.input = item.value("input", "");
                compReq.compilerFlags = item.value("flags", "");
                compReq.userId = request.value("userId", "anonymous");
                compReq.provider = item.value("provider", "auto");
                compReq.timestamp = std::chrono::system_clock::now();
                
                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    requestQueue.push(compReq);
                }
                
                response.push_back({{"requestId", compReq.id}});
            }
            
            queueCV.notify_all();
            res.set_content(response.dump(), "application/json");
        });
        
        // Mobile-optimized compilation (minimal output)
        server.Post("/api/compile/mobile", [this](const httplib::Request& req, httplib::Response& res) {
            json request = json::parse(req.body);
            
            // Quick compilation with reduced output
            CompilationRequest compReq;
            compReq.id = generateRequestId();
            compReq.language = request["language"];
            compReq.code = request["code"];
            compReq.input = "";
            compReq.compilerFlags = "-O2"; // Optimize for mobile
            compReq.userId = request.value("userId", "mobile");
            compReq.provider = "custom"; // Use our fast backend
            compReq.timestamp = std::chrono::system_clock::now();
            
            // Process immediately for mobile
            CompilationResult result = processCompilationImmediate(compReq);
            
            // Return minimal response
            json response = {
                {"success", result.exitCode == 0},
                {"output", truncateForMobile(result.output)},
                {"error", result.errors.empty() ? "" : result.errors.substr(0, 200)}
            };
            
            res.set_content(response.dump(), "application/json");
        });
        
        // Code templates
        server.Get("/api/templates/:language", [this](const httplib::Request& req, httplib::Response& res) {
            std::string language = req.matches[1];
            json templates = getCodeTemplates(language);
            res.set_content(templates.dump(), "application/json");
        });
        
        // Share compilation result
        server.Post("/api/share", [this](const httplib::Request& req, httplib::Response& res) {
            json request = json::parse(req.body);
            std::string shareId = createShareLink(request);
            
            res.set_content(json{{"shareUrl", "https://compile.vs2022.app/s/" + shareId}}.dump(), 
                          "application/json");
        });
    }
    
    void start(int port = 8081) {
        // Start compilation processor threads
        for (int i = 0; i < 4; ++i) {
            std::thread processor([this]() {
                processCompilationRequests();
            });
            processor.detach();
        }
        
        // Start rate limit reset thread
        std::thread rateLimitReset([this]() {
            resetRateLimits();
        });
        rateLimitReset.detach();
        
        std::cout << "🚀 Mobile Compiler Service starting on port " << port << std::endl;
        server.listen("0.0.0.0", port);
    }
    
private:
    void processCompilationRequests() {
        while (true) {
            CompilationRequest request;
            
            {
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCV.wait(lock, [this] { return !requestQueue.empty(); });
                
                request = requestQueue.front();
                requestQueue.pop();
            }
            
            // Select best provider
            std::string provider = selectProvider(request);
            
            CompilationResult result;
            
            if (provider == "custom") {
                result = compileWithCustomBackend(request);
            } else if (provider == "godbolt") {
                result = compileWithGodbolt(request);
            } else if (provider == "jdoodle") {
                result = compileWithJDoodle(request);
            } else if (provider == "wandbox") {
                result = compileWithWandbox(request);
            } else if (provider == "judge0") {
                result = compileWithJudge0(request);
            }
            
            // Cache result
            {
                std::lock_guard<std::mutex> lock(cacheMutex);
                resultsCache[request.id] = result;
            }
        }
    }
    
    CompilationResult compileWithCustomBackend(const CompilationRequest& request) {
        CompilationResult result;
        result.id = request.id;
        result.provider = "custom";
        
        try {
            // Create isolated environment
            std::string workDir = sandboxPath + request.id;
            fs::create_directories(workDir);
            
            // Determine file extension
            std::string ext = getFileExtension(request.language);
            std::string sourceFile = workDir + "/source" + ext;
            std::string inputFile = workDir + "/input.txt";
            std::string outputFile = workDir + "/output.txt";
            
            // Write source code
            std::ofstream src(sourceFile);
            src << request.code;
            src.close();
            
            // Write input if provided
            if (!request.input.empty()) {
                std::ofstream inp(inputFile);
                inp << request.input;
                inp.close();
            }
            
            // Build compile command
            std::string compileCmd = buildCompileCommand(request.language, sourceFile, 
                                                        workDir + "/program", request.compilerFlags);
            
            // Compile
            auto start = std::chrono::high_resolution_clock::now();
            int compileResult = system((compileCmd + " 2>" + workDir + "/compile_errors.txt").c_str());
            
            if (compileResult != 0) {
                std::ifstream errFile(workDir + "/compile_errors.txt");
                std::stringstream buffer;
                buffer << errFile.rdbuf();
                result.errors = buffer.str();
                result.exitCode = compileResult;
                
                // Cleanup
                fs::remove_all(workDir);
                return result;
            }
            
            // Execute with timeout and resource limits
            std::string execCmd = createSecureExecutionCommand(workDir + "/program", 
                                                             inputFile, outputFile);
            
            int execResult = system(execCmd.c_str());
            auto end = std::chrono::high_resolution_clock::now();
            
            result.executionTime = std::chrono::duration<double>(end - start).count();
            result.exitCode = execResult;
            
            // Read output
            std::ifstream outFile(outputFile);
            std::stringstream outBuffer;
            outBuffer << outFile.rdbuf();
            result.output = outBuffer.str();
            
            // Generate assembly if requested
            if (request.compilerFlags.find("-S") != std::string::npos) {
                result.assemblyOutput = generateAssembly(sourceFile, request.language);
            }
            
            // Cleanup
            fs::remove_all(workDir);
            
        } catch (const std::exception& e) {
            result.errors = "Internal error: " + std::string(e.what());
            result.exitCode = -1;
        }
        
        return result;
    }
    
    std::string buildCompileCommand(const std::string& language, const std::string& sourceFile,
                                   const std::string& outputFile, const std::string& flags) {
        if (language == "c++" || language == "cpp") {
            return "g++ -std=c++17 " + flags + " " + sourceFile + " -o " + outputFile;
        } else if (language == "c") {
            return "gcc -std=c11 " + flags + " " + sourceFile + " -o " + outputFile;
        } else if (language == "rust") {
            return "rustc " + flags + " " + sourceFile + " -o " + outputFile;
        } else if (language == "go") {
            return "go build " + flags + " -o " + outputFile + " " + sourceFile;
        } else if (language == "python") {
            return "python3 -m py_compile " + sourceFile; // Just syntax check
        } else if (language == "java") {
            return "javac " + flags + " " + sourceFile;
        }
        
        return "";
    }
    
    std::string createSecureExecutionCommand(const std::string& program, 
                                           const std::string& input, 
                                           const std::string& output) {
        // Use timeout, memory limits, and sandboxing
        std::string cmd = "timeout 5s ";  // 5 second timeout
        
        #ifdef __linux__
        // Linux: Use cgroups and namespaces for better isolation
        cmd += "firejail --quiet --private --net=none ";
        cmd += "--rlimit-as=512000000 ";  // 512MB memory limit
        cmd += "--rlimit-cpu=5 ";         // 5 second CPU time
        #endif
        
        cmd += program;
        
        if (!input.empty()) {
            cmd += " < " + input;
        }
        
        cmd += " > " + output + " 2>&1";
        
        return cmd;
    }
    
    CompilationResult compileWithGodbolt(const CompilationRequest& request) {
        CompilationResult result;
        result.id = request.id;
        result.provider = "godbolt";
        
        // Prepare request
        json godboltRequest = {
            {"source", request.code},
            {"options", {
                {"userArguments", request.compilerFlags},
                {"executeParameters", {
                    {"stdin", request.input}
                }},
                {"compilerOptions", {
                    {"executorRequest", true}
                }}
            }}
        };
        
        // Select compiler ID based on language
        std::string compilerId = getGodboltCompilerId(request.language);
        
        // Make API request
        httplib::Client client("https://godbolt.org");
        auto res = client.Post("/api/compiler/" + compilerId + "/compile", 
                              godboltRequest.dump(), "application/json");
        
        if (res && res->status == 200) {
            json response = json::parse(res->body);
            
            if (response.contains("stdout")) {
                result.output = response["stdout"];
            }
            if (response.contains("stderr")) {
                result.errors = response["stderr"];
            }
            if (response.contains("code")) {
                result.exitCode = response["code"];
            }
            if (response.contains("asm")) {
                result.assemblyOutput = response["asm"];
            }
        }
        
        return result;
    }
    
    std::string selectProvider(const CompilationRequest& request) {
        if (request.provider != "auto") {
            return request.provider;
        }
        
        // Select based on language support and availability
        for (const auto& [name, provider] : providers) {
            auto& langs = provider.supportedLanguages;
            if (std::find(langs.begin(), langs.end(), request.language) != langs.end()) {
                // Check rate limit
                if (checkProviderAvailability(name)) {
                    return name;
                }
            }
        }
        
        return "custom"; // Fallback to our backend
    }
    
    bool checkRateLimit(const std::string& userId) {
        std::lock_guard<std::mutex> lock(rateLimitMutex);
        
        if (userRequestCount[userId] >= 50) { // 50 requests per minute
            return false;
        }
        
        userRequestCount[userId]++;
        return true;
    }
    
    void resetRateLimits() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::minutes(1));
            
            std::lock_guard<std::mutex> lock(rateLimitMutex);
            userRequestCount.clear();
        }
    }
    
    std::string generateRequestId() {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
        return "req_" + std::to_string(ms.count());
    }
    
    void createSandboxEnvironment() {
        fs::create_directories(sandboxPath);
        
        #ifdef __linux__
        // Set up Linux-specific sandboxing
        system("sudo apt-get install -y firejail > /dev/null 2>&1");
        #endif
    }
    
    json getCompilerOptions(const std::string& language) {
        json options = {
            {"optimizationLevels", {"-O0", "-O1", "-O2", "-O3", "-Os"}},
            {"warnings", {"-Wall", "-Wextra", "-Werror"}},
            {"standards", {}}
        };
        
        if (language == "c++") {
            options["standards"] = {"c++11", "c++14", "c++17", "c++20", "c++23"};
            options["features"] = {"-pthread", "-fopenmp", "-fcoroutines"};
        } else if (language == "c") {
            options["standards"] = {"c89", "c99", "c11", "c17"};
        }
        
        return options;
    }
    
    json getCodeTemplates(const std::string& language) {
        json templates = json::array();
        
        if (language == "c++") {
            templates.push_back({
                {"name", "Hello World"},
                {"code", "#include <iostream>\n\nint main() {\n    std::cout << \"Hello, World!\" << std::endl;\n    return 0;\n}"}
            });
            
            templates.push_back({
                {"name", "Competitive Programming"},
                {"code", "#include <bits/stdc++.h>\nusing namespace std;\n\nint main() {\n    ios_base::sync_with_stdio(false);\n    cin.tie(NULL);\n    \n    // Your code here\n    \n    return 0;\n}"}
            });
        }
        
        return templates;
    }
    
    std::string truncateForMobile(const std::string& output) {
        if (output.length() <= 1000) return output;
        return output.substr(0, 1000) + "\n... (truncated)";
    }
    
    CompilationResult processCompilationImmediate(const CompilationRequest& request) {
        // Fast path for mobile requests
        return compileWithCustomBackend(request);
    }
};

// Standalone server
int main() {
    std::cout << "📱 Mobile Compiler Service - VS2022 Menu Encryptor Suite" << std::endl;
    std::cout << "🔧 Providing compilation for mobile devices worldwide" << std::endl;
    
    MobileCompilerService service;
    service.start(8081);
    
    return 0;
}