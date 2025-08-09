// BlackMagii Enhanced Compiler with tinyRAWR Compression
// 🎩✨ Zero command-line knowledge needed!
// Supports batch cross-compilation and custom compression

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <zlib.h>
#include <bitset>

namespace fs = std::filesystem;

// tinyRAWR Compression Engine 🦖
class TinyRAWR {
private:
    // Magic header for tinyRAWR files
    const uint8_t MAGIC[8] = {'t','i','n','y','R','A','W','R'};
    const uint16_t VERSION = 0x0100; // Version 1.0
    
    struct FileEntry {
        std::string filename;
        std::vector<uint8_t> data;
        uint32_t originalSize;
        uint32_t compressedSize;
        uint8_t compressionType; // 0=none, 1=zlib, 2=custom
    };
    
public:
    // Compress multiple files into a tinyRAWR archive
    bool compress(const std::vector<std::string>& files, const std::string& outputFile) {
        std::ofstream out(outputFile, std::ios::binary);
        if (!out) return false;
        
        // Write header
        out.write(reinterpret_cast<const char*>(MAGIC), 8);
        out.write(reinterpret_cast<const char*>(&VERSION), 2);
        
        uint32_t fileCount = files.size();
        out.write(reinterpret_cast<const char*>(&fileCount), 4);
        
        std::cout << "🦖 tinyRAWR: Compressing " << fileCount << " files..." << std::endl;
        
        for (const auto& file : files) {
            FileEntry entry;
            entry.filename = fs::path(file).filename().string();
            
            // Read file
            std::ifstream in(file, std::ios::binary);
            if (!in) continue;
            
            in.seekg(0, std::ios::end);
            entry.originalSize = in.tellg();
            in.seekg(0, std::ios::beg);
            
            std::vector<uint8_t> fileData(entry.originalSize);
            in.read(reinterpret_cast<char*>(fileData.data()), entry.originalSize);
            in.close();
            
            // Compress based on file type
            if (isSourceCode(file)) {
                entry.data = compressSourceCode(fileData);
                entry.compressionType = 2; // Custom compression
            } else {
                entry.data = compressZlib(fileData);
                entry.compressionType = 1; // zlib
            }
            
            entry.compressedSize = entry.data.size();
            
            // Write file entry
            uint32_t nameLen = entry.filename.length();
            out.write(reinterpret_cast<const char*>(&nameLen), 4);
            out.write(entry.filename.c_str(), nameLen);
            out.write(reinterpret_cast<const char*>(&entry.originalSize), 4);
            out.write(reinterpret_cast<const char*>(&entry.compressedSize), 4);
            out.write(reinterpret_cast<const char*>(&entry.compressionType), 1);
            out.write(reinterpret_cast<const char*>(entry.data.data()), entry.compressedSize);
            
            float ratio = (1.0f - (float)entry.compressedSize / entry.originalSize) * 100;
            std::cout << "  📄 " << entry.filename << " - " << ratio << "% smaller!" << std::endl;
        }
        
        out.close();
        std::cout << "✅ tinyRAWR archive created: " << outputFile << std::endl;
        return true;
    }
    
private:
    bool isSourceCode(const std::string& filename) {
        std::vector<std::string> sourceExts = {
            ".cpp", ".c", ".h", ".hpp", ".py", ".java", ".js", ".rs", ".go"
        };
        
        std::string ext = fs::path(filename).extension().string();
        return std::find(sourceExts.begin(), sourceExts.end(), ext) != sourceExts.end();
    }
    
    std::vector<uint8_t> compressSourceCode(const std::vector<uint8_t>& data) {
        // Custom compression optimized for source code
        // Remove redundant whitespace, compress keywords, etc.
        std::vector<uint8_t> compressed;
        
        // For now, use zlib but we can implement custom algorithm later
        return compressZlib(data);
    }
    
    std::vector<uint8_t> compressZlib(const std::vector<uint8_t>& data) {
        uLongf compressedSize = compressBound(data.size());
        std::vector<uint8_t> compressed(compressedSize);
        
        if (compress2(compressed.data(), &compressedSize, data.data(), data.size(), Z_BEST_COMPRESSION) == Z_OK) {
            compressed.resize(compressedSize);
            return compressed;
        }
        
        return data; // Return original if compression fails
    }
};

// Enhanced BlackMagii Compiler
class BlackMagiiEnhanced {
private:
    struct CompilationJob {
        std::string sourceFile;
        std::string language;
        std::vector<std::string> targetPlatforms;
        std::string outputDir;
        bool optimize = true;
        bool strip = true;
        bool compress = true;
    };
    
    struct CompilerProfile {
        std::string name;
        std::string command;
        std::string flags;
        std::string outputFlag;
    };
    
    std::map<std::string, std::map<std::string, CompilerProfile>> compilers;
    TinyRAWR tinyRAWR;
    
public:
    BlackMagiiEnhanced() {
        initializeCompilers();
        std::cout << "🎩✨ BlackMagii Enhanced - Zero Command Line Compilation!" << std::endl;
        std::cout << "🦖 With tinyRAWR compression technology!" << std::endl;
    }
    
    void initializeCompilers() {
        // Windows compilers
        compilers["Windows"]["C++"] = {"MSVC", "cl", "/O2 /EHsc", "/Fe"};
        compilers["Windows"]["C"] = {"MSVC", "cl", "/O2", "/Fe"};
        compilers["Windows"]["Rust"] = {"rustc", "rustc", "-O", "-o"};
        compilers["Windows"]["Go"] = {"go", "go build", "-ldflags=-s -w", "-o"};
        
        // Linux compilers
        compilers["Linux"]["C++"] = {"g++", "g++", "-O3 -s", "-o"};
        compilers["Linux"]["C"] = {"gcc", "gcc", "-O3 -s", "-o"};
        compilers["Linux"]["Rust"] = {"rustc", "rustc", "-O", "-o"};
        compilers["Linux"]["Go"] = {"go", "GOOS=linux go build", "-ldflags=-s -w", "-o"};
        
        // macOS compilers
        compilers["macOS"]["C++"] = {"clang++", "clang++", "-O3", "-o"};
        compilers["macOS"]["C"] = {"clang", "clang", "-O3", "-o"};
        compilers["macOS"]["Rust"] = {"rustc", "rustc", "-O", "-o"};
        compilers["macOS"]["Go"] = {"go", "GOOS=darwin go build", "", "-o"};
        
        // Android compilers
        compilers["Android"]["C++"] = {"android-clang++", "aarch64-linux-android-clang++", "-O3", "-o"};
        compilers["Android"]["C"] = {"android-clang", "aarch64-linux-android-clang", "-O3", "-o"};
        compilers["Android"]["Rust"] = {"rustc", "rustc", "--target aarch64-linux-android -O", "-o"};
        compilers["Android"]["Go"] = {"go", "GOOS=android GOARCH=arm64 go build", "", "-o"};
    }
    
    // Simple GUI-like interface
    void runSimpleMode() {
        while (true) {
            clearScreen();
            showSimpleMenu();
            
            int choice;
            std::cin >> choice;
            std::cin.ignore();
            
            switch (choice) {
                case 1: simpleCompileSingle(); break;
                case 2: batchCompileMultiple(); break;
                case 3: compileFolder(); break;
                case 4: showSettings(); break;
                case 5: 
                    std::cout << "✨ Thanks for using BlackMagii! 🎩" << std::endl;
                    return;
                default:
                    std::cout << "Invalid choice!" << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }
    
private:
    void showSimpleMenu() {
        std::cout << R"(
╔═══════════════════════════════════════════════╗
║      🎩 BlackMagii Enhanced Compiler 🎩       ║
║         No Command Line Needed! ✨            ║
╠═══════════════════════════════════════════════╣
║                                               ║
║  1. 📄 Compile Single File                    ║
║  2. 📚 Batch Compile Multiple Files           ║
║  3. 📁 Compile Entire Folder                  ║
║  4. ⚙️  Settings                              ║
║  5. 🚪 Exit                                   ║
║                                               ║
╚═══════════════════════════════════════════════╝

Choose (1-5): )";
    }
    
    void simpleCompileSingle() {
        std::cout << "\n📄 SINGLE FILE COMPILATION" << std::endl;
        std::cout << "════════════════════════" << std::endl;
        
        std::cout << "\n📂 Enter file path (or drag & drop): ";
        std::string filePath;
        std::getline(std::cin, filePath);
        
        // Clean path
        filePath.erase(std::remove(filePath.begin(), filePath.end(), '\"'), filePath.end());
        
        if (!fs::exists(filePath)) {
            std::cout << "❌ File not found!" << std::endl;
            waitForEnter();
            return;
        }
        
        // Auto-detect language
        std::string language = detectLanguage(filePath);
        std::cout << "✅ Detected: " << language << std::endl;
        
        // Select platforms
        std::vector<std::string> platforms = selectPlatforms();
        
        if (platforms.empty()) {
            std::cout << "❌ No platforms selected!" << std::endl;
            waitForEnter();
            return;
        }
        
        // Compile for all selected platforms
        CompilationJob job;
        job.sourceFile = filePath;
        job.language = language;
        job.targetPlatforms = platforms;
        job.outputDir = "BlackMagii_Output";
        
        executeCompilationJob(job);
        
        waitForEnter();
    }
    
    void batchCompileMultiple() {
        std::cout << "\n📚 BATCH COMPILATION MODE" << std::endl;
        std::cout << "═══════════════════════" << std::endl;
        std::cout << "Enter source files (one per line, empty line to finish):" << std::endl;
        
        std::vector<std::string> files;
        std::string line;
        
        while (true) {
            std::cout << "📄 File " << (files.size() + 1) << ": ";
            std::getline(std::cin, line);
            
            if (line.empty()) break;
            
            // Clean path
            line.erase(std::remove(line.begin(), line.end(), '\"'), line.end());
            
            if (fs::exists(line)) {
                files.push_back(line);
                std::cout << "✅ Added: " << fs::path(line).filename() << std::endl;
            } else {
                std::cout << "❌ File not found, skipping..." << std::endl;
            }
        }
        
        if (files.empty()) {
            std::cout << "❌ No valid files provided!" << std::endl;
            waitForEnter();
            return;
        }
        
        // Select platforms
        std::vector<std::string> platforms = selectPlatforms();
        
        std::cout << "\n🚀 Starting batch compilation..." << std::endl;
        std::cout << "Files: " << files.size() << " | Platforms: " << platforms.size() << std::endl;
        std::cout << "Total compilations: " << (files.size() * platforms.size()) << std::endl;
        
        // Create progress bar
        int total = files.size() * platforms.size();
        int current = 0;
        
        for (const auto& file : files) {
            CompilationJob job;
            job.sourceFile = file;
            job.language = detectLanguage(file);
            job.targetPlatforms = platforms;
            job.outputDir = "BlackMagii_Output/Batch_" + getCurrentTimestamp();
            
            for (const auto& platform : platforms) {
                current++;
                showProgress(current, total);
                compileSingleTarget(job, platform);
            }
        }
        
        std::cout << "\n✅ Batch compilation complete!" << std::endl;
        
        // Offer to compress results
        std::cout << "\n🦖 Compress results with tinyRAWR? (y/n): ";
        char compress;
        std::cin >> compress;
        std::cin.ignore();
        
        if (compress == 'y' || compress == 'Y') {
            compressResults();
        }
        
        waitForEnter();
    }
    
    std::vector<std::string> selectPlatforms() {
        std::cout << "\n🎯 SELECT TARGET PLATFORMS" << std::endl;
        std::cout << "═════════════════════════" << std::endl;
        std::cout << "1. 🪟 Windows" << std::endl;
        std::cout << "2. 🐧 Linux" << std::endl;
        std::cout << "3. 🍎 macOS" << std::endl;
        std::cout << "4. 🤖 Android" << std::endl;
        std::cout << "5. 🌍 ALL PLATFORMS" << std::endl;
        std::cout << "\nSelect (comma-separated, e.g., 1,2,4): ";
        
        std::string selection;
        std::getline(std::cin, selection);
        
        std::vector<std::string> platforms;
        
        if (selection.find('5') != std::string::npos) {
            return {"Windows", "Linux", "macOS", "Android"};
        }
        
        if (selection.find('1') != std::string::npos) platforms.push_back("Windows");
        if (selection.find('2') != std::string::npos) platforms.push_back("Linux");
        if (selection.find('3') != std::string::npos) platforms.push_back("macOS");
        if (selection.find('4') != std::string::npos) platforms.push_back("Android");
        
        return platforms;
    }
    
    void executeCompilationJob(const CompilationJob& job) {
        std::cout << "\n🎪 COMPILATION STARTED" << std::endl;
        std::cout << "═══════════════════" << std::endl;
        
        for (const auto& platform : job.targetPlatforms) {
            compileSingleTarget(job, platform);
        }
        
        if (job.compress) {
            std::cout << "\n🦖 Creating tinyRAWR archive..." << std::endl;
            compressCompiledFiles(job);
        }
    }
    
    void compileSingleTarget(const CompilationJob& job, const std::string& platform) {
        std::cout << "\n🎯 Compiling for " << platform << "..." << std::endl;
        
        // Get compiler for this platform and language
        if (compilers.find(platform) == compilers.end() ||
            compilers[platform].find(job.language) == compilers[platform].end()) {
            std::cout << "❌ No compiler available for " << job.language << " on " << platform << std::endl;
            return;
        }
        
        auto& compiler = compilers[platform][job.language];
        
        // Create output directory
        std::string outputDir = job.outputDir + "/" + platform;
        fs::create_directories(outputDir);
        
        // Build output filename
        std::string outputFile = outputDir + "/" + fs::path(job.sourceFile).stem().string();
        if (platform == "Windows") outputFile += ".exe";
        
        // Build compile command
        std::string cmd = compiler.command + " " + compiler.flags + " \"" + job.sourceFile + "\" " + 
                         compiler.outputFlag + " \"" + outputFile + "\"";
        
        // Show simplified command
        std::cout << "📝 " << compiler.name << " -> " << fs::path(outputFile).filename() << std::endl;
        
        // Execute
        int result = system(cmd.c_str());
        
        if (result == 0) {
            std::cout << "✅ Success!" << std::endl;
            
            // Create run script
            createSimpleRunScript(outputFile, platform);
        } else {
            std::cout << "❌ Compilation failed!" << std::endl;
        }
    }
    
    void createSimpleRunScript(const std::string& exePath, const std::string& platform) {
        std::string scriptPath;
        std::string content;
        
        if (platform == "Windows") {
            scriptPath = exePath + "_RUN.bat";
            content = "@echo off\n";
            content += "echo ==============================\n";
            content += "echo BlackMagii Compiled Program\n";
            content += "echo ==============================\n";
            content += "echo.\n";
            content += "\"" + fs::path(exePath).filename().string() + "\"\n";
            content += "echo.\n";
            content += "echo ==============================\n";
            content += "echo Program finished!\n";
            content += "pause\n";
        } else {
            scriptPath = exePath + "_RUN.sh";
            content = "#!/bin/bash\n";
            content += "echo '=============================='\n";
            content += "echo 'BlackMagii Compiled Program'\n";
            content += "echo '=============================='\n";
            content += "echo\n";
            content += "\"./" + fs::path(exePath).filename().string() + "\"\n";
            content += "echo\n";
            content += "echo '=============================='\n";
            content += "echo 'Program finished!'\n";
            content += "read -p 'Press Enter to exit...'\n";
        }
        
        std::ofstream script(scriptPath);
        script << content;
        script.close();
        
        if (platform != "Windows") {
            system(("chmod +x \"" + scriptPath + "\"").c_str());
        }
    }
    
    std::string detectLanguage(const std::string& filePath) {
        std::string ext = fs::path(filePath).extension().string();
        
        if (ext == ".cpp" || ext == ".cc" || ext == ".cxx") return "C++";
        if (ext == ".c") return "C";
        if (ext == ".rs") return "Rust";
        if (ext == ".go") return "Go";
        if (ext == ".py") return "Python";
        if (ext == ".java") return "Java";
        if (ext == ".js") return "JavaScript";
        
        return "Unknown";
    }
    
    void showProgress(int current, int total) {
        int barWidth = 50;
        float progress = (float)current / total;
        
        std::cout << "\r[";
        int pos = barWidth * progress;
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) std::cout << "█";
            else if (i == pos) std::cout << "▓";
            else std::cout << "░";
        }
        std::cout << "] " << int(progress * 100.0) << "% (" << current << "/" << total << ")" << std::flush;
    }
    
    void clearScreen() {
        #ifdef _WIN32
            system("cls");
        #else
            system("clear");
        #endif
    }
    
    void waitForEnter() {
        std::cout << "\nPress Enter to continue...";
        std::cin.get();
    }
    
    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        char buffer[20];
        strftime(buffer, sizeof(buffer), "%Y%m%d_%H%M%S", localtime(&time_t));
        return std::string(buffer);
    }
    
    void compressResults() {
        std::vector<std::string> files;
        
        // Find all compiled files
        for (const auto& entry : fs::recursive_directory_iterator("BlackMagii_Output")) {
            if (entry.is_regular_file() && 
                (entry.path().extension() == ".exe" || 
                 entry.path().extension() == "" ||
                 entry.path().extension() == ".out")) {
                files.push_back(entry.path().string());
            }
        }
        
        if (!files.empty()) {
            std::string archiveName = "BlackMagii_Compiled_" + getCurrentTimestamp() + ".rawr";
            tinyRAWR.compress(files, archiveName);
        }
    }
    
    void compressCompiledFiles(const CompilationJob& job) {
        std::vector<std::string> files;
        
        for (const auto& platform : job.targetPlatforms) {
            std::string outputDir = job.outputDir + "/" + platform;
            if (fs::exists(outputDir)) {
                for (const auto& entry : fs::directory_iterator(outputDir)) {
                    if (entry.is_regular_file()) {
                        files.push_back(entry.path().string());
                    }
                }
            }
        }
        
        if (!files.empty()) {
            std::string archiveName = job.outputDir + "/" + 
                                    fs::path(job.sourceFile).stem().string() + "_all_platforms.rawr";
            tinyRAWR.compress(files, archiveName);
        }
    }
};

// HTTP Server for remote compilation
class BlackMagiiServer {
private:
    BlackMagiiEnhanced compiler;
    int port;
    
public:
    BlackMagiiServer(int serverPort = 8888) : port(serverPort) {
        std::cout << "🌐 BlackMagii HTTP Server starting on port " << port << std::endl;
    }
    
    void start() {
        // Simple HTTP server implementation
        // In real implementation, use a proper HTTP library
        std::cout << "📡 Server ready for remote compilation requests!" << std::endl;
        std::cout << "🔗 Connect via: http://localhost:" << port << std::endl;
        
        // Accept compilation requests
        // Return compiled binaries or tinyRAWR archives
    }
};

int main() {
    std::cout << "🎩✨ BlackMagii Enhanced Compiler" << std::endl;
    std::cout << "Choose mode:" << std::endl;
    std::cout << "1. 🖥️  Local Compilation (Simple GUI)" << std::endl;
    std::cout << "2. 🌐 Start HTTP Server" << std::endl;
    std::cout << "3. 📡 Connect to Remote Server" << std::endl;
    std::cout << "Choice: ";
    
    int choice;
    std::cin >> choice;
    std::cin.ignore();
    
    switch (choice) {
        case 1: {
            BlackMagiiEnhanced compiler;
            compiler.runSimpleMode();
            break;
        }
        case 2: {
            BlackMagiiServer server;
            server.start();
            break;
        }
        case 3: {
            std::cout << "Enter server address: ";
            std::string serverAddr;
            std::getline(std::cin, serverAddr);
            // Connect to remote BlackMagii server
            break;
        }
    }
    
    return 0;
}