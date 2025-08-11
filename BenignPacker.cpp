/*
========================================================================================
BENIGN PACKER - MAIN APPLICATION
========================================================================================
FEATURES:
- Plugin system integration
- UniqueStub71Plugin support
- MASM Assembler Plugin support
- Visual Studio 2022 Native Compilation
========================================================================================
*/

#include <iostream>
#include <fstream>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

// Include the plugin framework
#include "PluginFramework/IPlugin.h"

// Include plugin implementations
#include "UniqueStub71Plugin.h"
#include "MASMAssemblerPlugin.cpp"

using namespace BenignPacker::PluginFramework;

class BenignPackerApp {
private:
    std::map<std::string, std::unique_ptr<IStubGenerator>> plugins;
    std::map<std::string, std::string> settings;

public:
    BenignPackerApp() {
        InitializePlugins();
        LoadDefaultSettings();
    }

    ~BenignPackerApp() {
        for (auto& [name, plugin] : plugins) {
            if (plugin) {
                plugin->OnUnload();
            }
        }
    }

    void InitializePlugins() {
        // Initialize UniqueStub71Plugin
        auto uniqueStubPlugin = std::make_unique<BenignPacker::UniqueStub71Plugin>();
        if (uniqueStubPlugin->OnLoad()) {
            plugins["UniqueStub71"] = std::move(uniqueStubPlugin);
            std::cout << "Loaded UniqueStub71Plugin" << std::endl;
        }

        // Initialize MASMAssemblerPlugin
        auto masmPlugin = std::make_unique<BenignPacker::MASMAssemblerPlugin>();
        if (masmPlugin->OnLoad()) {
            plugins["MASMAssembler"] = std::move(masmPlugin);
            std::cout << "Loaded MASMAssemblerPlugin" << std::endl;
        }
    }

    void LoadDefaultSettings() {
        settings["output_format"] = "exe";
        settings["optimization_level"] = "2";
        settings["enable_encryption"] = "true";
        settings["enable_polymorphic"] = "true";
        settings["enable_anti_analysis"] = "true";
    }

    bool ProcessFile(const std::string& inputFile, const std::string& outputFile, const std::string& method = "advanced") {
        // Read input file
        std::ifstream file(inputFile, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open input file '" << inputFile << "'" << std::endl;
            return false;
        }

        std::vector<uint8_t> payloadData((std::istreambuf_iterator<char>(file)),
                                        std::istreambuf_iterator<char>());
        file.close();

        // Create execution context
        ExecutionContext context;
        context.input_file = inputFile;
        context.output_file = outputFile;
        context.payload_data = payloadData;
        context.parameters = settings;
        context.parameters["method"] = method;
        context.verbose_mode = true;
        context.debug_mode = false;

        // Try to process with each plugin
        for (auto& [name, plugin] : plugins) {
            if (!plugin) continue;

            std::cout << "Trying plugin: " << name << std::endl;

            // Initialize plugin with settings
            if (!plugin->Initialize(settings)) {
                std::cerr << "Failed to initialize plugin: " << name << std::endl;
                continue;
            }

            // Execute plugin
            PluginResult result = plugin->Execute(context);

            if (result.success) {
                // Write output file
                std::ofstream outFile(outputFile, std::ios::binary);
                if (outFile.is_open()) {
                    outFile.write(reinterpret_cast<const char*>(result.output_data.data()), 
                                 result.output_data.size());
                    outFile.close();

                    std::cout << "Success: " << result.message << std::endl;
                    std::cout << "Input size: " << payloadData.size() << " bytes" << std::endl;
                    std::cout << "Output size: " << result.output_data.size() << " bytes" << std::endl;
                    std::cout << "Method used: " << method << std::endl;
                    std::cout << "Plugin used: " << name << std::endl;
                    return true;
                } else {
                    std::cerr << "Error: Cannot write output file '" << outputFile << "'" << std::endl;
                    return false;
                }
            } else {
                std::cerr << "Plugin " << name << " failed: " << result.message << std::endl;
                if (!result.error_details.empty()) {
                    std::cerr << "Details: " << result.error_details << std::endl;
                }
            }
        }

        std::cerr << "All plugins failed to process the file" << std::endl;
        return false;
    }

    void ShowHelp() {
        std::cout << "BenignPacker - Advanced Stub Generation Framework" << std::endl;
        std::cout << "=================================================" << std::endl;
        std::cout << "Usage: BenignPacker.exe <input_file> [output_file] [method]" << std::endl;
        std::cout << std::endl;
        std::cout << "Methods:" << std::endl;
        std::cout << "  default  - Basic stub generation" << std::endl;
        std::cout << "  advanced - Full features (recommended)" << std::endl;
        std::cout << "  mutex    - Focus on mutex protection" << std::endl;
        std::cout << "  stealth  - Maximum anti-analysis" << std::endl;
        std::cout << std::endl;
        std::cout << "Supported formats: .bin, .exe, .dll, .raw, .shellcode" << std::endl;
        std::cout << std::endl;
        std::cout << "Examples:" << std::endl;
        std::cout << "  BenignPacker.exe payload.bin" << std::endl;
        std::cout << "  BenignPacker.exe payload.bin output.exe advanced" << std::endl;
        std::cout << "  BenignPacker.exe payload.bin stealth_output.exe stealth" << std::endl;
    }

    void ShowPluginInfo() {
        std::cout << "Loaded Plugins:" << std::endl;
        std::cout << "===============" << std::endl;
        
        for (const auto& [name, plugin] : plugins) {
            if (!plugin) continue;
            
            PluginConfig config = plugin->GetConfig();
            std::cout << "Name: " << config.name << std::endl;
            std::cout << "Version: " << config.version << std::endl;
            std::cout << "Description: " << config.description << std::endl;
            std::cout << "Author: " << config.author << std::endl;
            std::cout << "Supported formats: ";
            for (const auto& format : config.supported_formats) {
                std::cout << format << " ";
            }
            std::cout << std::endl;
            std::cout << "Supported methods: ";
            for (const auto& method : config.supported_methods) {
                std::cout << method << " ";
            }
            std::cout << std::endl;
            std::cout << "Capabilities: " << static_cast<uint32_t>(config.capabilities) << std::endl;
            std::cout << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    std::cout << "BenignPacker - Advanced Stub Generation Framework" << std::endl;
    std::cout << "Version 1.0.0 - Built with Visual Studio 2022" << std::endl;
    std::cout << "=================================================" << std::endl;

    BenignPackerApp app;

    // Show plugin information
    app.ShowPluginInfo();

    if (argc < 2) {
        app.ShowHelp();
        return 1;
    }

    std::string inputFile = argv[1];
    std::string outputFile = (argc > 2) ? argv[2] : "output.exe";
    std::string method = (argc > 3) ? argv[3] : "advanced";

    // Check if input file exists
    if (!std::filesystem::exists(inputFile)) {
        std::cerr << "Error: Input file '" << inputFile << "' not found!" << std::endl;
        return 1;
    }

    std::cout << "Processing file: " << inputFile << std::endl;
    std::cout << "Output file: " << outputFile << std::endl;
    std::cout << "Method: " << method << std::endl;
    std::cout << "=================================================" << std::endl;

    // Process the file
    if (app.ProcessFile(inputFile, outputFile, method)) {
        std::cout << "=================================================" << std::endl;
        std::cout << "Success! Generated file: " << outputFile << std::endl;
        return 0;
    } else {
        std::cout << "=================================================" << std::endl;
        std::cout << "Failed to process file!" << std::endl;
        return 1;
    }
}