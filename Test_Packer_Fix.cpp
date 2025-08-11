#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>

class PackerFixTester {
public:
    static bool testGeneratedSource(const std::string& sourceFile) {
        std::cout << "=== TESTING PACKER-GENERATED SOURCE ===" << std::endl;
        std::cout << "File: " << sourceFile << std::endl;
        
        // Read the generated source file
        std::ifstream file(sourceFile);
        if (!file) {
            std::cout << "❌ Cannot open source file: " << sourceFile << std::endl;
            return false;
        }
        
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();
        
        // Count main functions
        int mainCount = countMainFunctions(content);
        std::cout << "Main functions found: " << mainCount << std::endl;
        
        if (mainCount == 0) {
            std::cout << "❌ ERROR: No main function found!" << std::endl;
            return false;
        } else if (mainCount > 1) {
            std::cout << "❌ ERROR: Multiple main functions found (" << mainCount << ")!" << std::endl;
            showMainFunctionLocations(content);
            return false;
        } else {
            std::cout << "✅ SUCCESS: Exactly one main function found!" << std::endl;
        }
        
        // Check for common syntax issues
        if (checkSyntaxIssues(content)) {
            std::cout << "✅ No obvious syntax issues detected" << std::endl;
        } else {
            std::cout << "⚠️  Potential syntax issues detected" << std::endl;
        }
        
        // Check for required includes
        if (checkRequiredIncludes(content)) {
            std::cout << "✅ Required includes present" << std::endl;
        } else {
            std::cout << "⚠️  Missing required includes" << std::endl;
        }
        
        return mainCount == 1;
    }
    
private:
    static int countMainFunctions(const std::string& content) {
        int count = 0;
        size_t pos = 0;
        
        // Look for "int main(" patterns
        while ((pos = content.find("int main(", pos)) != std::string::npos) {
            count++;
            pos += 9; // Length of "int main("
        }
        
        return count;
    }
    
    static void showMainFunctionLocations(const std::string& content) {
        std::cout << "\nMain function locations:" << std::endl;
        size_t pos = 0;
        int lineNum = 1;
        int mainNum = 1;
        
        while ((pos = content.find("int main(", pos)) != std::string::npos) {
            // Count lines up to this position
            int currentLine = std::count(content.begin(), content.begin() + pos, '\n') + 1;
            
            std::cout << "Main function #" << mainNum << " at line " << currentLine << std::endl;
            
            // Show some context
            size_t lineStart = content.rfind('\n', pos) + 1;
            size_t lineEnd = content.find('\n', pos);
            if (lineEnd == std::string::npos) lineEnd = content.length();
            
            std::string line = content.substr(lineStart, lineEnd - lineStart);
            std::cout << "  " << line << std::endl;
            
            mainNum++;
            pos += 9;
        }
    }
    
    static bool checkSyntaxIssues(const std::string& content) {
        // Check for common syntax issues
        
        // Check for variables starting with numbers
        if (content.find("int ") != std::string::npos) {
            size_t pos = 0;
            while ((pos = content.find("int ", pos)) != std::string::npos) {
                pos += 4; // Skip "int "
                
                // Find the variable name
                while (pos < content.length() && std::isspace(content[pos])) pos++;
                
                if (pos < content.length() && std::isdigit(content[pos])) {
                    std::cout << "⚠️  Found variable starting with digit at position " << pos << std::endl;
                    return false;
                }
                
                // Find end of this variable declaration
                while (pos < content.length() && content[pos] != ';' && content[pos] != '\n') pos++;
            }
        }
        
        // Check for unmatched braces
        int braceCount = 0;
        for (char c : content) {
            if (c == '{') braceCount++;
            if (c == '}') braceCount--;
        }
        
        if (braceCount != 0) {
            std::cout << "⚠️  Unmatched braces detected (balance: " << braceCount << ")" << std::endl;
            return false;
        }
        
        return true;
    }
    
    static bool checkRequiredIncludes(const std::string& content) {
        bool hasWindows = content.find("#include <windows.h>") != std::string::npos;
        bool hasStdio = content.find("#include <stdio.h>") != std::string::npos || 
                       content.find("#include <iostream>") != std::string::npos;
        
        if (!hasWindows) {
            std::cout << "⚠️  Missing #include <windows.h>" << std::endl;
        }
        
        if (!hasStdio) {
            std::cout << "⚠️  Missing stdio or iostream include" << std::endl;
        }
        
        return hasWindows && hasStdio;
    }
};

int main(int argc, char* argv[]) {
    std::cout << "=== PACKER SOURCE CODE TESTER ===" << std::endl;
    
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <generated_source_file.cpp>" << std::endl;
        std::cout << "Example: " << argv[0] << " temp_ygY46YXG.cpp" << std::endl;
        return 1;
    }
    
    std::string sourceFile = argv[1];
    
    if (PackerFixTester::testGeneratedSource(sourceFile)) {
        std::cout << "\n🎉 SUCCESS: Generated source code is valid!" << std::endl;
        std::cout << "The packer fix is working correctly." << std::endl;
        return 0;
    } else {
        std::cout << "\n❌ FAILURE: Generated source code has issues!" << std::endl;
        std::cout << "The packer needs additional fixes." << std::endl;
        return 1;
    }
}