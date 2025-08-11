/*
========================================================================================
IPLUGIN.H - PLUGIN INTERFACE FOR BENIGN PACKER INTEGRATION
========================================================================================
FEATURES:
- Base plugin interface for BenignPacker integration
- Plugin configuration and execution context structures
- Plugin result handling
- Visual Studio 2022 Native Compilation
========================================================================================
*/

#ifndef IPLUGIN_H
#define IPLUGIN_H

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <memory>

namespace BenignPacker {

// Forward declarations
class IStubGenerator;
class PluginFramework;

// Plugin configuration structure
struct PluginConfig {
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::vector<std::string> supportedFormats;
    std::map<std::string, std::string> capabilities;
    bool requiresAdmin;
    bool supportsEncryption;
    bool supportsPolymorphic;
    bool supportsAntiAnalysis;
};

// Execution context for plugin operations
struct ExecutionContext {
    std::string inputFile;
    std::string outputFile;
    std::string method;
    std::map<std::string, std::string> parameters;
    bool verbose;
    bool debug;
    std::vector<std::string> additionalOptions;
};

// Plugin execution result
struct PluginResult {
    bool success;
    std::string message;
    std::vector<uint8_t> generatedData;
    std::map<std::string, std::string> metadata;
    int exitCode;
    std::string errorDetails;
};

// Base plugin interface
class IPlugin {
public:
    virtual ~IPlugin() = default;
    virtual PluginConfig GetConfig() const = 0;
    virtual bool Initialize(const std::map<std::string, std::string>& settings) = 0;
    virtual PluginResult Execute(const ExecutionContext& context) = 0;
};

// Stub generator interface
class IStubGenerator : public IPlugin {
public:
    virtual ~IStubGenerator() = default;
    virtual std::vector<uint8_t> GenerateStub(const std::vector<uint8_t>& payload) = 0;
};

// Plugin framework class
class PluginFramework {
public:
    PluginFramework();
    ~PluginFramework();
    
    bool LoadPlugin(const std::string& pluginPath);
    bool UnloadPlugin(const std::string& pluginName);
    std::vector<std::string> GetLoadedPlugins() const;
    std::unique_ptr<IStubGenerator> CreateStubGenerator(const std::string& pluginName);
    
private:
    std::map<std::string, std::unique_ptr<IPlugin>> loadedPlugins;
};

} // namespace BenignPacker

#endif // IPLUGIN_H