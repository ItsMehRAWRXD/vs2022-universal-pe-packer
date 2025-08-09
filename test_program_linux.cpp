#include <iostream>
#include <ctime>
#include <unistd.h>

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "🔥 ENCRYPTED PROGRAM RUNNING! 🔥" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Show current time
    time_t now = time(0);
    std::cout << "Current time: " << ctime(&now);
    
    // Show process ID
    std::cout << "Process ID: " << getpid() << std::endl;
    
    // Show that decryption worked
    std::cout << "✅ File successfully decrypted and executed!" << std::endl;
    std::cout << "✅ This proves the encryption system works!" << std::endl;
    
    std::cout << "========================================" << std::endl;
    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}