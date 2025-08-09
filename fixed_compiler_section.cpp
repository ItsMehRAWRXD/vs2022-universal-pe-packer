// Fixed Compiler Section for VS2022_GUI_Benign_Packer.cpp
// This replaces the Windows-specific compilation commands with cross-platform alternatives

private:
    bool createPortableCompilerBatch() {
        // Updated batch script that works on both Windows and Linux
        std::string batchScript = R"(@echo off
REM Portable Compiler Batch - Cross-Platform PE Generator
REM Arguments: %1 = source file, %2 = output executable

REM Windows-specific compilers
REM Try Visual Studio first (Windows only)
where cl.exe >nul 2>&1
if %errorlevel% == 0 (
    cl /nologo /O2 /DNDEBUG /MD %1 /Fe%2 /link /SUBSYSTEM:CONSOLE user32.lib kernel32.lib advapi32.lib shell32.lib >nul 2>&1
    if %errorlevel% == 0 exit /b 0
)

REM Try MinGW-w64 (Windows)
where gcc.exe >nul 2>&1
if %errorlevel% == 0 (
    gcc -O2 -DNDEBUG -static-libgcc -static-libstdc++ %1 -o %2 -luser32 -lkernel32 -ladvapi32 -lshell32 >nul 2>&1
    if %errorlevel% == 0 exit /b 0
    
    g++ -O2 -DNDEBUG -static-libgcc -static-libstdc++ %1 -o %2 -luser32 -lkernel32 -ladvapi32 -lshell32 >nul 2>&1
    if %errorlevel% == 0 exit /b 0
)

REM Try TCC (Tiny C Compiler)
where tcc.exe >nul 2>&1
if %errorlevel% == 0 (
    tcc -O2 %1 -o %2 -luser32 -lkernel32 -ladvapi32 >nul 2>&1
    if %errorlevel% == 0 exit /b 0
)

exit /b 1
)";
        
        std::ofstream batchFile("portable_compiler.bat");
        if (batchFile.is_open()) {
            batchFile << batchScript;
            batchFile.close();
            return true;
        }
        
        return false;
    }
    
    CompilerResult compileToExecutable(const std::string& sourceCode, const std::string& outputPath) {
        CompilerResult result;
        result.success = false;
        result.outputPath = outputPath;
        
        // Create temporary source file
        std::string tempSource = "temp_" + randomEngine.generateRandomName() + ".cpp";
        std::ofstream sourceFile(tempSource);
        if (!sourceFile.is_open()) {
            result.errorMessage = "Failed to create temporary source file";
            return result;
        }
        sourceFile << sourceCode;
        sourceFile.close();
        
        // Try multiple compilation methods (CROSS-PLATFORM)
        std::vector<std::string> compileCommands;
        
        #ifdef _WIN32
        // Windows compilation commands
        compileCommands = {
            // Visual Studio (if available)
            "cl /nologo /O2 /DNDEBUG /MD \"" + tempSource + "\" /Fe\"" + outputPath + "\" /link /SUBSYSTEM:CONSOLE user32.lib kernel32.lib advapi32.lib shell32.lib ole32.lib >nul 2>&1",
            
            // MinGW-w64 (Windows)
            "g++ -O2 -DNDEBUG -static-libgcc -static-libstdc++ \"" + tempSource + "\" -o \"" + outputPath + "\" -luser32 -lkernel32 -ladvapi32 -lshell32 -lole32 >nul 2>&1",
            
            // TCC (Tiny C Compiler)
            "tcc -O2 \"" + tempSource + "\" -o \"" + outputPath + "\" -luser32 -lkernel32 -ladvapi32 >nul 2>&1",
            
            // Fallback portable compiler
            "portable_compiler.bat \"" + tempSource + "\" \"" + outputPath + "\" >nul 2>&1"
        };
        #else
        // Linux cross-compilation commands (MinGW-w64)
        compileCommands = {
            // MinGW-w64 x86_64 (most common)
            "x86_64-w64-mingw32-g++ -O2 -DNDEBUG -static-libgcc -static-libstdc++ \"" + tempSource + "\" -o \"" + outputPath + "\" -luser32 -lkernel32 -ladvapi32 -lshell32 -lole32 2>/dev/null",
            
            // MinGW-w64 i686 (32-bit)
            "i686-w64-mingw32-g++ -O2 -DNDEBUG -static-libgcc -static-libstdc++ \"" + tempSource + "\" -o \"" + outputPath + "\" -luser32 -lkernel32 -ladvapi32 -lshell32 -lole32 2>/dev/null",
            
            // Alternative MinGW-w64 commands
            "x86_64-w64-mingw32-gcc -O2 -DNDEBUG -static-libgcc -static-libstdc++ \"" + tempSource + "\" -o \"" + outputPath + "\" -luser32 -lkernel32 -ladvapi32 -lstdc++ 2>/dev/null"
        };
        #endif
        
        // Try each compiler in order
        for (const auto& cmd : compileCommands) {
            int compileResult = system(cmd.c_str());
            if (compileResult == 0) {
                // Verify the executable was created
                #ifdef _WIN32
                if (GetFileAttributesA(outputPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                #else
                struct stat buffer;
                if (stat(outputPath.c_str(), &buffer) == 0) {
                #endif
                    result.success = true;
                    result.errorMessage = "Compilation successful using cross-platform compiler";
                    break;
                }
            }
        }
        
        // Clean up temporary file
        #ifdef _WIN32
        DeleteFileA(tempSource.c_str());
        #else
        unlink(tempSource.c_str());
        #endif
        
        if (!result.success) {
            result.errorMessage = "All compilation methods failed. Please install MinGW-w64 or Visual Studio Build Tools.";
        }
        
        return result;
    }