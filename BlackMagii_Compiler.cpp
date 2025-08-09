// BlackMagii Compiler - The Swiss Army Knife of Compilers
// 🎩✨ Making compilation magical across all platforms
// Supports: C/C++, Python, Java, Rust, Go, AutoIt, and more!
// With full emoji support! 🚀

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <regex>
#include <thread>
#include <chrono>
#include <algorithm>
#include <memory>
#include <sstream>
#include <locale>
#include <codecvt>

// Platform detection
#ifdef _WIN32
    #include <windows.h>
    #define PLATFORM "Windows"
#elif __APPLE__
    #include <TargetConditionals.h>
    #define PLATFORM "macOS"
#elif __linux__
    #include <unistd.h>
    #define PLATFORM "Linux"
#elif __ANDROID__
    #define PLATFORM "Android"
#else
    #define PLATFORM "Unknown"
#endif

namespace fs = std::filesystem;

class BlackMagiiCompiler {
private:
    // Language definitions with emoji identifiers! 🎨
    struct Language {
        std::string name;
        std::string emoji;
        std::vector<std::string> extensions;
        std::string compileCommand;
        std::string runCommand;
        bool needsCompilation;
        std::map<std::string, std::string> platformCommands;
    };
    
    std::map<std::string, Language> languages;
    
    // User preferences
    struct UserPreferences {
        std::map<std::string, std::string> customCompilers;
        std::vector<std::string> favoriteSearchSites;
        std::map<std::string, std::string> emojiAliases;
        bool enableMagicMode = true;
        bool verboseOutput = false;
        std::string preferredTheme = "dark";
    };
    
    UserPreferences prefs;
    
    // Compilation cache
    std::map<std::string, std::string> compilationCache;
    
    // Search engines (NOT MSDN! 😄)
    std::vector<std::string> searchEngines = {
        "https://stackoverflow.com/search?q=",
        "https://github.com/search?q=",
        "https://duckduckgo.com/?q=site:cppreference.com+",
        "https://www.google.com/search?q=-site:msdn.microsoft.com+"
    };
    
public:
    BlackMagiiCompiler() {
        initializeLanguages();
        loadUserPreferences();
        setupEmojiSupport();
        
        std::cout << "🎩✨ BlackMagii Compiler v1.0 - Making compilation magical!" << std::endl;
        std::cout << "🌍 Platform: " << PLATFORM << std::endl;
        std::cout << "🚀 Ready to compile with emoji support!" << std::endl << std::endl;
    }
    
    void initializeLanguages() {
        // C++ with full emoji support
        languages["cpp"] = {
            "C++", "⚡", {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".h"},
            "g++ -std=c++20 -O2", "./a.out", true,
            {
                {"Windows", "cl /std:c++20 /O2"},
                {"macOS", "clang++ -std=c++20 -O2"},
                {"Linux", "g++ -std=c++20 -O2"},
                {"Android", "aarch64-linux-android-clang++ -std=c++20"}
            }
        };
        
        // Python - the snake! 🐍
        languages["python"] = {
            "Python", "🐍", {".py", ".pyw"},
            "python3", "python3", false,
            {
                {"Windows", "python"},
                {"macOS", "python3"},
                {"Linux", "python3"},
                {"Android", "python3"}
            }
        };
        
        // Java - coffee time! ☕
        languages["java"] = {
            "Java", "☕", {".java"},
            "javac", "java", true,
            {
                {"Windows", "javac"},
                {"macOS", "javac"},
                {"Linux", "javac"},
                {"Android", "javac"}
            }
        };
        
        // Rust - the crab! 🦀
        languages["rust"] = {
            "Rust", "🦀", {".rs"},
            "rustc -O", "./main", true,
            {
                {"Windows", "rustc -O"},
                {"macOS", "rustc -O"},
                {"Linux", "rustc -O"},
                {"Android", "rustc --target aarch64-linux-android"}
            }
        };
        
        // Go - the gopher! 🐹
        languages["go"] = {
            "Go", "🐹", {".go"},
            "go build", "./main", true,
            {
                {"Windows", "go build"},
                {"macOS", "go build"},
                {"Linux", "go build"},
                {"Android", "GOOS=android GOARCH=arm64 go build"}
            }
        };
        
        // AutoIt - automation magic! 🤖
        languages["autoit"] = {
            "AutoIt", "🤖", {".au3"},
            "Aut2exe.exe /in", "start", true,
            {
                {"Windows", "Aut2exe.exe /in"},
                {"macOS", "wine Aut2exe.exe /in"},
                {"Linux", "wine Aut2exe.exe /in"}
            }
        };
        
        // JavaScript/Node - the yellow box! 📦
        languages["javascript"] = {
            "JavaScript", "📦", {".js", ".mjs"},
            "node", "node", false,
            {
                {"Windows", "node"},
                {"macOS", "node"},
                {"Linux", "node"},
                {"Android", "node"}
            }
        };
        
        // Assembly - the gear! ⚙️
        languages["assembly"] = {
            "Assembly", "⚙️", {".asm", ".s"},
            "nasm -f elf64", "./a.out", true,
            {
                {"Windows", "nasm -f win64"},
                {"macOS", "nasm -f macho64"},
                {"Linux", "nasm -f elf64"},
                {"Android", "as"}
            }
        };
        
        // Add more languages...
    }
    
    void run() {
        while (true) {
            showMagicalMenu();
            
            int choice;
            std::cin >> choice;
            std::cin.ignore();
            
            switch (choice) {
                case 1: compileSingleFile(); break;
                case 2: compileProject(); break;
                case 3: autoDetectAndCompile(); break;
                case 4: crossCompile(); break;
                case 5: androidDeploy(); break;
                case 6: webAssemblyCompile(); break;
                case 7: searchAndLearn(); break;
                case 8: customizeCompiler(); break;
                case 9: emojiCodeMode(); break;
                case 10: batchCompileAll(); break;
                case 11: createInstaller(); break;
                case 12: retroMode(); break;
                case 0: 
                    std::cout << "✨ Thanks for using BlackMagii! Stay magical! 🎩" << std::endl;
                    return;
                default:
                    std::cout << "❌ Invalid choice! Try again! 🔄" << std::endl;
            }
        }
    }
    
private:
    void showMagicalMenu() {
        std::cout << "\n🎩✨ BlackMagii Compiler - Main Menu ✨🎩" << std::endl;
        std::cout << "═══════════════════════════════════════" << std::endl;
        std::cout << "1️⃣  Single File Compilation (One & Done) 📄" << std::endl;
        std::cout << "2️⃣  Project Compilation 📁" << std::endl;
        std::cout << "3️⃣  Auto-Detect & Compile 🔍" << std::endl;
        std::cout << "4️⃣  Cross-Compile for Any OS 🌍" << std::endl;
        std::cout << "5️⃣  Android Deployment 📱" << std::endl;
        std::cout << "6️⃣  WebAssembly Compilation 🌐" << std::endl;
        std::cout << "7️⃣  Search & Learn (No MSDN!) 🔎" << std::endl;
        std::cout << "8️⃣  Customize Your Compiler ⚙️" << std::endl;
        std::cout << "9️⃣  Emoji Code Mode 😎" << std::endl;
        std::cout << "🔟 Batch Compile Everything! 🚀" << std::endl;
        std::cout << "1️⃣1️⃣ Create Installer Package 📦" << std::endl;
        std::cout << "1️⃣2️⃣ RetRo Command Line Mode 💻" << std::endl;
        std::cout << "0️⃣  Exit 👋" << std::endl;
        std::cout << "═══════════════════════════════════════" << std::endl;
        std::cout << "Choose your magic: ";
    }
    
    void compileSingleFile() {
        std::cout << "\n🎯 Single File Compilation Mode!" << std::endl;
        std::cout << "Enter file path (or drag & drop): ";
        
        std::string filePath;
        std::getline(std::cin, filePath);
        
        // Remove quotes if present
        filePath.erase(std::remove(filePath.begin(), filePath.end(), '\"'), filePath.end());
        
        if (!fs::exists(filePath)) {
            std::cout << "❌ File not found! Let me search for solutions... 🔍" << std::endl;
            searchForHelp("file not found compilation error");
            return;
        }
        
        // Detect language
        std::string ext = fs::path(filePath).extension().string();
        std::string detectedLang = detectLanguage(ext);
        
        if (detectedLang.empty()) {
            std::cout << "🤔 Unknown file type! Searching online..." << std::endl;
            searchForHelp("how to compile " + ext + " files");
            return;
        }
        
        Language& lang = languages[detectedLang];
        std::cout << lang.emoji << " Detected: " << lang.name << std::endl;
        
        // Show target OS options
        std::cout << "\n🎯 Target OS:" << std::endl;
        std::cout << "1. Current OS (" << PLATFORM << ")" << std::endl;
        std::cout << "2. Windows 🪟" << std::endl;
        std::cout << "3. Linux 🐧" << std::endl;
        std::cout << "4. macOS 🍎" << std::endl;
        std::cout << "5. Android 🤖" << std::endl;
        std::cout << "6. All of them! 🌍" << std::endl;
        std::cout << "Choice: ";
        
        int osChoice;
        std::cin >> osChoice;
        std::cin.ignore();
        
        if (osChoice == 6) {
            compileForAllPlatforms(filePath, lang);
        } else {
            std::string targetOS = getTargetOS(osChoice);
            compileFile(filePath, lang, targetOS);
        }
    }
    
    void compileFile(const std::string& filePath, const Language& lang, const std::string& targetOS) {
        std::cout << "\n🎪 Starting magical compilation..." << std::endl;
        
        // Create output directory
        std::string outputDir = "BlackMagii_Output/" + targetOS;
        fs::create_directories(outputDir);
        
        // Get compile command for target OS
        std::string compileCmd = lang.platformCommands.count(targetOS) > 0 
            ? lang.platformCommands.at(targetOS) 
            : lang.compileCommand;
        
        // Add file path
        compileCmd += " \"" + filePath + "\"";
        
        // Add output flag
        std::string outputFile = outputDir + "/" + fs::path(filePath).stem().string();
        if (targetOS == "Windows") outputFile += ".exe";
        
        if (lang.needsCompilation) {
            compileCmd += " -o \"" + outputFile + "\"";
        }
        
        // Show the magic happening
        std::cout << "✨ Casting spell: " << compileCmd << std::endl;
        animateCompilation();
        
        // Execute compilation
        int result = system(compileCmd.c_str());
        
        if (result == 0) {
            std::cout << "\n✅ Compilation successful! 🎉" << std::endl;
            std::cout << "📦 Output: " << outputFile << std::endl;
            
            // Create batch/shell script
            createRunScript(outputFile, targetOS);
            
            // Offer to run
            std::cout << "\n🏃 Run it now? (y/n): ";
            char runChoice;
            std::cin >> runChoice;
            std::cin.ignore();
            
            if (runChoice == 'y' || runChoice == 'Y') {
                runProgram(outputFile, lang, targetOS);
            }
        } else {
            std::cout << "\n❌ Compilation failed! 😢" << std::endl;
            std::cout << "🔍 Searching for solutions..." << std::endl;
            
            // Smart error search
            std::string errorQuery = lang.name + " compilation error " + std::to_string(result);
            searchForHelp(errorQuery);
        }
    }
    
    void compileForAllPlatforms(const std::string& filePath, const Language& lang) {
        std::cout << "\n🌍 Cross-platform compilation activated!" << std::endl;
        
        std::vector<std::string> platforms = {"Windows", "Linux", "macOS", "Android"};
        
        for (const auto& platform : platforms) {
            std::cout << "\n🎯 Compiling for " << platform << "..." << std::endl;
            compileFile(filePath, lang, platform);
        }
        
        std::cout << "\n🎉 All platforms compiled! Check BlackMagii_Output folder!" << std::endl;
    }
    
    void autoDetectAndCompile() {
        std::cout << "\n🔍 Auto-detecting source files in current directory..." << std::endl;
        
        std::map<std::string, std::vector<fs::path>> detectedFiles;
        
        // Scan directory
        for (const auto& entry : fs::directory_iterator(".")) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                std::string lang = detectLanguage(ext);
                
                if (!lang.empty()) {
                    detectedFiles[lang].push_back(entry.path());
                }
            }
        }
        
        if (detectedFiles.empty()) {
            std::cout << "❌ No source files found!" << std::endl;
            return;
        }
        
        // Show detected files
        std::cout << "\n📊 Found:" << std::endl;
        for (const auto& [lang, files] : detectedFiles) {
            std::cout << languages[lang].emoji << " " << languages[lang].name 
                     << ": " << files.size() << " files" << std::endl;
        }
        
        std::cout << "\n🎯 Compile all? (y/n): ";
        char choice;
        std::cin >> choice;
        std::cin.ignore();
        
        if (choice == 'y' || choice == 'Y') {
            for (const auto& [lang, files] : detectedFiles) {
                for (const auto& file : files) {
                    compileFile(file.string(), languages[lang], PLATFORM);
                }
            }
        }
    }
    
    void androidDeploy() {
        std::cout << "\n📱 Android Deployment Mode!" << std::endl;
        
        // Check for Android SDK
        if (system("adb version > nul 2>&1") != 0) {
            std::cout << "❌ Android SDK not found! Let me help..." << std::endl;
            searchForHelp("install Android SDK command line");
            return;
        }
        
        std::cout << "📁 Select source file or APK: ";
        std::string filePath;
        std::getline(std::cin, filePath);
        
        // Remove quotes
        filePath.erase(std::remove(filePath.begin(), filePath.end(), '\"'), filePath.end());
        
        if (fs::path(filePath).extension() == ".apk") {
            // Direct APK installation
            installAPK(filePath);
        } else {
            // Compile for Android first
            std::string ext = fs::path(filePath).extension().string();
            std::string lang = detectLanguage(ext);
            
            if (!lang.empty()) {
                compileFile(filePath, languages[lang], "Android");
                
                // Package as APK
                std::cout << "\n📦 Creating APK package..." << std::endl;
                createAndroidPackage(filePath);
            }
        }
    }
    
    void emojiCodeMode() {
        std::cout << "\n😎 Emoji Code Mode Activated! 🚀" << std::endl;
        std::cout << "Now you can use emojis in your code!" << std::endl;
        
        std::cout << "\n📝 Example C++ with emojis:" << std::endl;
        std::cout << "```cpp" << std::endl;
        std::cout << "#include <iostream>" << std::endl;
        std::cout << "int main() {" << std::endl;
        std::cout << "    int 🍎 = 5;  // apple count" << std::endl;
        std::cout << "    int 🍌 = 3;  // banana count" << std::endl;
        std::cout << "    std::cout << \"Total fruits: \" << 🍎 + 🍌 << \" 🍓\" << std::endl;" << std::endl;
        std::cout << "    return 0;" << std::endl;
        std::cout << "}" << std::endl;
        std::cout << "```" << std::endl;
        
        std::cout << "\n🎨 Create emoji-enhanced code? (y/n): ";
        char choice;
        std::cin >> choice;
        std::cin.ignore();
        
        if (choice == 'y' || choice == 'Y') {
            createEmojiCode();
        }
    }
    
    void searchAndLearn() {
        std::cout << "\n🔍 Search & Learn Mode (MSDN-free zone! 😄)" << std::endl;
        std::cout << "What do you want to learn? ";
        
        std::string query;
        std::getline(std::cin, query);
        
        searchForHelp(query);
    }
    
    void searchForHelp(const std::string& query) {
        std::cout << "\n🌐 Searching the web (avoiding MSDN)..." << std::endl;
        
        // Use preferred search sites
        for (const auto& engine : searchEngines) {
            std::string searchUrl = engine + urlEncode(query);
            std::cout << "🔗 " << searchUrl << std::endl;
            
            // Open in default browser
            #ifdef _WIN32
                system(("start " + searchUrl).c_str());
                break; // One search is enough on Windows
            #elif __APPLE__
                system(("open " + searchUrl).c_str());
                break;
            #elif __linux__
                system(("xdg-open " + searchUrl).c_str());
                break;
            #endif
        }
        
        // Also search GitHub for code examples
        std::cout << "\n📚 Searching GitHub for examples..." << std::endl;
        std::string githubSearch = "https://github.com/search?q=" + urlEncode(query) + "&type=code";
        
        #ifdef _WIN32
            system(("start " + githubSearch).c_str());
        #elif __APPLE__
            system(("open " + githubSearch).c_str());
        #elif __linux__
            system(("xdg-open " + githubSearch).c_str());
        #endif
    }
    
    void customizeCompiler() {
        std::cout << "\n⚙️ Customize BlackMagii Compiler!" << std::endl;
        std::cout << "1. Add custom compiler 🔧" << std::endl;
        std::cout << "2. Add favorite search site 🔍" << std::endl;
        std::cout << "3. Create emoji alias 😊" << std::endl;
        std::cout << "4. Import compiler config 📥" << std::endl;
        std::cout << "5. Export current config 📤" << std::endl;
        std::cout << "Choice: ";
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        switch (choice) {
            case 1: addCustomCompiler(); break;
            case 2: addSearchSite(); break;
            case 3: createEmojiAlias(); break;
            case 4: importConfig(); break;
            case 5: exportConfig(); break;
        }
        
        saveUserPreferences();
    }
    
    void retroMode() {
        std::cout << "\n💻 RetRo Command Line Mode!" << std::endl;
        std::cout << "Classic compilation experience with modern power!" << std::endl;
        
        while (true) {
            std::cout << "\nRetRo> ";
            std::string command;
            std::getline(std::cin, command);
            
            if (command == "exit" || command == "quit") break;
            
            if (command.substr(0, 7) == "compile") {
                // Extract filename
                std::string filename = command.substr(8);
                retroCompile(filename);
            }
            else if (command == "help") {
                showRetroHelp();
            }
            else if (command.substr(0, 6) == "google") {
                std::string query = command.substr(7);
                searchForHelp(query);
            }
            else {
                std::cout << "Unknown command. Type 'help' for commands." << std::endl;
            }
        }
    }
    
    void createRunScript(const std::string& outputFile, const std::string& targetOS) {
        std::string scriptPath;
        std::string scriptContent;
        
        if (targetOS == "Windows") {
            scriptPath = outputFile + "_run.bat";
            scriptContent = "@echo off\n";
            scriptContent += "echo 🎯 Running " + outputFile + "...\n";
            scriptContent += "\"" + outputFile + "\"\n";
            scriptContent += "echo.\n";
            scriptContent += "echo ✅ Program finished!\n";
            scriptContent += "pause\n";
        } else {
            scriptPath = outputFile + "_run.sh";
            scriptContent = "#!/bin/bash\n";
            scriptContent += "echo '🎯 Running " + outputFile + "...'\n";
            scriptContent += "\"" + outputFile + "\"\n";
            scriptContent += "echo\n";
            scriptContent += "echo '✅ Program finished!'\n";
            scriptContent += "read -p 'Press enter to continue...'\n";
        }
        
        std::ofstream script(scriptPath);
        script << scriptContent;
        script.close();
        
        if (targetOS != "Windows") {
            system(("chmod +x " + scriptPath).c_str());
        }
        
        std::cout << "📜 Created run script: " << scriptPath << std::endl;
    }
    
    void animateCompilation() {
        std::vector<std::string> frames = {
            "🎩✨", "🎩🌟", "🎩⚡", "🎩🔥", "🎩💫"
        };
        
        for (int i = 0; i < 10; i++) {
            std::cout << "\r" << frames[i % frames.size()] << " Compiling... " << std::flush;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        std::cout << "\r                    \r" << std::flush;
    }
    
    std::string detectLanguage(const std::string& extension) {
        for (const auto& [key, lang] : languages) {
            if (std::find(lang.extensions.begin(), lang.extensions.end(), extension) != lang.extensions.end()) {
                return key;
            }
        }
        return "";
    }
    
    std::string urlEncode(const std::string& str) {
        std::string encoded;
        for (char c : str) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded += c;
            } else if (c == ' ') {
                encoded += '+';
            } else {
                encoded += '%';
                encoded += "0123456789ABCDEF"[(c >> 4) & 0xF];
                encoded += "0123456789ABCDEF"[c & 0xF];
            }
        }
        return encoded;
    }
    
    void setupEmojiSupport() {
        // Enable UTF-8 console output
        #ifdef _WIN32
            SetConsoleCP(CP_UTF8);
            SetConsoleOutputCP(CP_UTF8);
        #endif
        
        std::locale::global(std::locale(""));
    }
    
    void loadUserPreferences() {
        // Load from BlackMagii_config.json if exists
        if (fs::exists("BlackMagii_config.json")) {
            std::ifstream config("BlackMagii_config.json");
            // Parse JSON config
            config.close();
        }
    }
    
    void saveUserPreferences() {
        std::ofstream config("BlackMagii_config.json");
        // Save preferences as JSON
        config.close();
    }
};

// Main entry point
int main() {
    // Set up UTF-8 for emoji support
    #ifdef _WIN32
        SetConsoleCP(CP_UTF8);
        SetConsoleOutputCP(CP_UTF8);
    #endif
    
    BlackMagiiCompiler compiler;
    compiler.run();
    
    return 0;
}