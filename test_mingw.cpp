#include <iostream>
#include <windows.h>

int main() {
    std::cout << "Hello from Windows PE compiled with MinGW-w64!" << std::endl;
    MessageBoxA(NULL, "MinGW-w64 cross-compilation successful!", "Test", MB_OK);
    return 0;
}