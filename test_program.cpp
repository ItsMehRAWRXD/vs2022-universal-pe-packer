#include <iostream>
#include <windows.h>

int main() {
    std::cout << "Hello! This is a test program." << std::endl;
    std::cout << "Current time: " << GetTickCount() << std::endl;
    std::cout << "This program was successfully decrypted and executed!" << std::endl;
    
    MessageBoxA(NULL, "Encrypted program running successfully!", "PE Encryptor Test", MB_OK | MB_ICONINFORMATION);
    
    std::cout << "Press any key to exit..." << std::endl;
    system("pause");
    
    return 0;
}