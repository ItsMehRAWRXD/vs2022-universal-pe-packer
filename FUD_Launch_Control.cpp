#include <windows.h>
#include <iostream>

// Controlled Launch FUD Template - Prevents Multiple Executions
class ControlledLaunchFUD {
private:
    static bool isAlreadyRunning() {
        // Create a named mutex to prevent multiple instances
        HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\FUD_SingleInstance_Mutex");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            CloseHandle(hMutex);
            return true; // Already running
        }
        return false; // First instance
    }
    
public:
    static void executeControlledPayload() {
        // Check if already running
        if (isAlreadyRunning()) {
            // Exit silently if another instance is running
            ExitProcess(0);
        }
        
        // Add a small delay to prevent rapid successive launches
        Sleep(1000);
        
        // Your payload execution here
        MessageBoxA(NULL, 
            "System validation completed successfully.\n"
            "Security checks passed.", 
            "System Validation", 
            MB_OK | MB_ICONINFORMATION);
        
        // Optional: Clean up and exit
        ExitProcess(0);
    }
    
    // Alternative: Controlled background execution
    static void executeInBackground() {
        if (isAlreadyRunning()) {
            ExitProcess(0);
        }
        
        // Run payload silently in background
        // No UI, no multiple launches
        
        // Your stealth payload here
        Sleep(2000); // Simulate background work
        
        ExitProcess(0);
    }
};

// Test the controlled launch
int main() {
    std::cout << "Testing Controlled Launch FUD..." << std::endl;
    
    // This will only run once, even if called multiple times
    ControlledLaunchFUD::executeControlledPayload();
    
    return 0;
}

// Template for WinMain version
/*
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Single instance check
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\FUD_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0; // Exit if already running
    }
    
    // Your FUD payload here
    ControlledLaunchFUD::executeControlledPayload();
    
    CloseHandle(hMutex);
    return 0;
}
*/