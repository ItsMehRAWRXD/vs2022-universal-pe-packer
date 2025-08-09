/*
 * MASM 2035 - Basic Usage Example
 * Demonstrates how to use the UniqueStub71Plugin
 */

#include "../src/include/UniqueStub71Plugin.h"
#include <iostream>
#include <fstream>

int main() {
    std::cout << "MASM 2035 - Advanced Stub Generation Framework" << std::endl;
    std::cout << "=============================================" << std::endl;

    try {
        // Initialize the plugin
        auto plugin = std::make_unique<BenignPacker::UniqueStub71Plugin>();
        
        std::map<std::string, std::string> settings;
        settings["verbose"] = "true";
        settings["target_size"] = "491793";
        
        if (!plugin->Initialize(settings)) {
            std::cerr << "Failed to initialize plugin" << std::endl;
            return 1;
        }

        // Load a payload file
        std::ifstream file("payload.bin", std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to open payload.bin" << std::endl;
            return 1;
        }

        std::vector<uint8_t> payload((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
        file.close();

        std::cout << "Loaded payload: " << payload.size() << " bytes" << std::endl;

        // Generate advanced stub with all features
        auto stub_data = plugin->GenerateAdvancedStub(payload);
        
        std::cout << "Generated stub: " << stub_data.size() << " bytes" << std::endl;

        // Apply company profile spoofing
        auto company_profile = plugin->GetRandomCompanyProfile();
        std::cout << "Using company profile: " << company_profile.name << std::endl;

        // Write output
        std::ofstream output("output.exe", std::ios::binary);
        output.write(reinterpret_cast<const char*>(stub_data.data()), stub_data.size());
        output.close();

        std::cout << "✅ Successfully generated protected executable!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
