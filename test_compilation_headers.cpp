#include <iostream>
#include "tiny_loader.h"
#include "cross_platform_encryption.h"
#include "enhanced_loader_utils.h"

// Test the enum definitions
enum ExploitDeliveryType {
    EXPLOIT_NONE = 0,
    EXPLOIT_HTML_SVG = 1,
    EXPLOIT_WIN_R = 2,
    EXPLOIT_INK_URL = 3,
    EXPLOIT_DOC_XLS = 4,
    EXPLOIT_XLL = 5
};

int main() {
    std::cout << "Testing header compilation..." << std::endl;
    
    // Test tiny_loader
    std::cout << "tiny_loader_bin_len: " << tiny_loader_bin_len << std::endl;
    
    // Test enum values
    std::cout << "EXPLOIT_HTML_SVG: " << EXPLOIT_HTML_SVG << std::endl;
    std::cout << "EXPLOIT_WIN_R: " << EXPLOIT_WIN_R << std::endl;
    std::cout << "EXPLOIT_INK_URL: " << EXPLOIT_INK_URL << std::endl;
    std::cout << "EXPLOIT_DOC_XLS: " << EXPLOIT_DOC_XLS << std::endl;
    
    // Test encryption metadata
    EncryptionMetadata metadata;
    metadata.method = static_cast<uint32_t>(EnhancedEncryptionMethod::XOR);
    metadata.keySize = 32;
    metadata.ivSize = 16;
    metadata.payloadSize = 1024;
    
    std::cout << "EncryptionMetadata test: " << metadata.method << std::endl;
    
    std::cout << "All header tests passed!" << std::endl;
    return 0;
}