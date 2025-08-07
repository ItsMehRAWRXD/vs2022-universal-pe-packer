#ifdef _WIN32
#include <windows.h>
#endif
#include <iostream>
#include <string>
#include <vector>

// Stealth stub with randomized API resolution and XOR obfuscation
int main() {
    // Randomized Dynamic API Resolution for stealth
    {
        auto xor_decrypt_plguCGyd = [](const unsigned char* data, size_t len) -> std::string {
            std::string result;
            if (len > 0) {
                unsigned char key = data[len - 1];
                result.resize(len - 1);
                for (size_t i = 0; i < len - 1; i++) {
                    result[i] = static_cast<char>(data[i] ^ key);
                }
            }
            return result;
        };

        const unsigned char k32_data_EayjGoFriBHqtE[] = {0xAB, 0xA5, 0xB2, 0xAE, 0xA5, 0xAC, 0xF3, 0xF2, 0xEE, 0xA4, 0xAC, 0xAC, 0xC0};
        const unsigned char gtc_data_JgtyjBzfgwEiuhl[] = {0xE2, 0xC0, 0xD1, 0xF1, 0xCC, 0xC6, 0xCE, 0xE6, 0xCA, 0xD0, 0xCB, 0xD1, 0xA5};
        const unsigned char slp_data_iClHtaAAfhI[] = {0x9E, 0xA1, 0xA8, 0xA8, 0xBD, 0xCD};

        // Anti-debugging timing check
        DWORD tck_qCsADhFHpcIgtx1 = GetTickCount();
        Sleep(2);
        DWORD tck_qCsADhFHpcIgtx2 = GetTickCount();
        if ((tck_qCsADhFHpcIgtx2 - tck_qCsADhFHpcIgtx1) > 12) {
            return; // Possible debugger detected
        }

        const unsigned char mod_data_gxcxerasbkm[] = {0x49, 0x47, 0x50, 0x4C, 0x47, 0x4E, 0x11, 0x10, 0x0C, 0x46, 0x4E, 0x4E, 0x22};
        HMODULE hMod_owsvwzppl = LoadLibraryA(xor_decrypt_CCjrbuIdwFFqqk(mod_data_ukenFIlsv, sizeof(mod_data_FAAwouAv)).c_str());
        if (hMod_owsvwzppl) {
            const unsigned char func_data_AlmpFnEFCu[] = {0xC8, 0xEA, 0xFB, 0xCC, 0xFA, 0xFD, 0xFD, 0xEA, 0xE1, 0xFB, 0xDB, 0xE7, 0xFD, 0xEA, 0xEE, 0xEB, 0xC6, 0xEB, 0x8F};
            FARPROC func_htaCkHfvoeIBpxir = GetProcAddress(hMod_owsvwzppl, xor_decrypt_okgywskjzpd(func_data_HpdprgwBimbijFuc, sizeof(func_data_oeiEhButy)).c_str());
            if (func_htaCkHfvoeIBpxir) {
            }
            const unsigned char func_data_uoggEFgeAGhgIEui[] = {0x25, 0x07, 0x16, 0x21, 0x17, 0x10, 0x10, 0x07, 0x0C, 0x16, 0x32, 0x10, 0x0D, 0x01, 0x07, 0x11, 0x11, 0x2B, 0x06, 0x62};
            FARPROC func_rybwimikjnB = GetProcAddress(hMod_owsvwzppl, xor_decrypt_GJFjojaganmyzzwF(func_data_wEoAxCfjzbaJH, sizeof(func_data_gagimjGffIaad)).c_str());
            if (func_rybwimikjnB) {
            }
            const unsigned char func_data_AJEyaudpnEeC[] = {0x25, 0x1A, 0x13, 0x13, 0x06, 0x76};
            FARPROC func_CucAssdrxyfok = GetProcAddress(hMod_owsvwzppl, xor_decrypt_CbcxpDcHjtjtzai(func_data_dkltBmugGnl, sizeof(func_data_twjdyrBtgmj)).c_str());
            if (func_CucAssdrxyfok) {
                typedef void(WINAPI* SleepProc)(DWORD);
                SleepProc slp_bDHbuGbbwyprxE = (SleepProc)func_CucAssdrxyfok;
                slp_bDHbuGbbwyprxE(5);
            }
            const unsigned char func_data_zfqkAbusAAhhthEs[] = {0xA8, 0x8A, 0x9B, 0xBB, 0x86, 0x8C, 0x84, 0xAC, 0x80, 0x9A, 0x81, 0x9B, 0xEF};
            FARPROC func_BcvacwvxAgh = GetProcAddress(hMod_owsvwzppl, xor_decrypt_ysBihGjjxvaH(func_data_fzxqqeFHEbb, sizeof(func_data_ltzrksEBbCre)).c_str());
            if (func_BcvacwvxAgh) {
                typedef DWORD(WINAPI* GetTickCountProc)();
                GetTickCountProc proc_lwgxIqFFgGHhx = (GetTickCountProc)func_BcvacwvxAgh;
                DWORD res_fnioovGA = proc_lwgxIqFFgGHhx();
                (void)res_fnioovGA; // Use the result
            }
            FreeLibrary(hMod_owsvwzppl);
        }

        const unsigned char mod_data_EaDDEqfzp[] = {0x12, 0x14, 0x02, 0x15, 0x54, 0x55, 0x49, 0x03, 0x0B, 0x0B, 0x67};
        HMODULE hMod_IAqtxkGG = LoadLibraryA(xor_decrypt_FyEDxmHzAzsCm(mod_data_nhbnprqagwb, sizeof(mod_data_anoHwojydn)).c_str());
        if (hMod_IAqtxkGG) {
            const unsigned char func_data_ykaEccFyg[] = {0xE6, 0xC4, 0xD5, 0xE2, 0xD4, 0xD3, 0xD3, 0xC4, 0xCF, 0xD5, 0xF1, 0xD3, 0xCE, 0xC2, 0xC4, 0xD2, 0xD2, 0xE8, 0xC5, 0xA1};
            FARPROC func_bzvxusjnoGvuxl = GetProcAddress(hMod_IAqtxkGG, xor_decrypt_pyqxwqypxdtbrIob(func_data_ymxgBzilnDu, sizeof(func_data_xjDacoCvcBEli)).c_str());
            if (func_bzvxusjnoGvuxl) {
            }
            const unsigned char func_data_tbtavEfIwm[] = {0xEF, 0xD0, 0xD9, 0xD9, 0xCC, 0xBC};
            FARPROC func_btmxqsbifAb = GetProcAddress(hMod_IAqtxkGG, xor_decrypt_ulxpddsjHrqkbp(func_data_JDdAllrcxB, sizeof(func_data_jtBAAGaEziaIj)).c_str());
            if (func_btmxqsbifAb) {
                typedef void(WINAPI* SleepProc)(DWORD);
                SleepProc slp_bDHbuGbbwyprxE = (SleepProc)func_btmxqsbifAb;
                slp_bDHbuGbbwyprxE(4);
            }
            const unsigned char func_data_wCCvtDDjJcnGd[] = {0x5C, 0x7E, 0x6F, 0x58, 0x6E, 0x69, 0x69, 0x7E, 0x75, 0x6F, 0x4F, 0x73, 0x69, 0x7E, 0x7A, 0x7F, 0x52, 0x7F, 0x1B};
            FARPROC func_aIaFBadCFrfJ = GetProcAddress(hMod_IAqtxkGG, xor_decrypt_JqBougzvI(func_data_nvinfpIndAcw, sizeof(func_data_IycBIqpvwcnf)).c_str());
            if (func_aIaFBadCFrfJ) {
            }
            const unsigned char func_data_Jovcxczxknv[] = {0x7D, 0x5F, 0x4E, 0x6E, 0x53, 0x59, 0x51, 0x79, 0x55, 0x4F, 0x54, 0x4E, 0x3A};
            FARPROC func_GrqzBtwnFnbF = GetProcAddress(hMod_IAqtxkGG, xor_decrypt_ynhespqpG(func_data_mHaJdIxdIxDCA, sizeof(func_data_HABzzEncaGcl)).c_str());
            if (func_GrqzBtwnFnbF) {
                typedef DWORD(WINAPI* GetTickCountProc)();
                GetTickCountProc proc_lwgxIqFFgGHhx = (GetTickCountProc)func_GrqzBtwnFnbF;
                DWORD res_fnioovGA = proc_lwgxIqFFgGHhx();
                (void)res_fnioovGA; // Use the result
            }
            FreeLibrary(hMod_IAqtxkGG);
        }

        const unsigned char mod_data_iElDBcHtJ[] = {0x6A, 0x70, 0x60, 0x68, 0x68, 0x2A, 0x60, 0x68, 0x68, 0x04};
        HMODULE hMod_yDmtiBCtlymEnu = LoadLibraryA(xor_decrypt_GDsDvkusBflE(mod_data_uEbJDioI, sizeof(mod_data_rcpkplDDBmJ)).c_str());
        if (hMod_yDmtiBCtlymEnu) {
            const unsigned char func_data_HBigGJurDGbICo[] = {0x7D, 0x5F, 0x4E, 0x79, 0x4F, 0x48, 0x48, 0x5F, 0x54, 0x4E, 0x6A, 0x48, 0x55, 0x59, 0x5F, 0x49, 0x49, 0x73, 0x5E, 0x3A};
            FARPROC func_triwacBwlpzEuFq = GetProcAddress(hMod_yDmtiBCtlymEnu, xor_decrypt_errwiomtCoIs(func_data_DabAhAskzwmG, sizeof(func_data_ctxBGszzktD)).c_str());
            if (func_triwacBwlpzEuFq) {
            }
            const unsigned char func_data_EkigcvEFFzmBuvDd[] = {0xA2, 0x9D, 0x94, 0x94, 0x81, 0xF1};
            FARPROC func_rpFCCvjoqEBEI = GetProcAddress(hMod_yDmtiBCtlymEnu, xor_decrypt_btqbhtqya(func_data_IIypzGvuBps, sizeof(func_data_zovhAdxglpsoj)).c_str());
            if (func_rpFCCvjoqEBEI) {
                typedef void(WINAPI* SleepProc)(DWORD);
                SleepProc slp_bDHbuGbbwyprxE = (SleepProc)func_rpFCCvjoqEBEI;
                slp_bDHbuGbbwyprxE(4);
            }
            const unsigned char func_data_ogevsfACoBmaf[] = {0x69, 0x4B, 0x5A, 0x7A, 0x47, 0x4D, 0x45, 0x6D, 0x41, 0x5B, 0x40, 0x5A, 0x2E};
            FARPROC func_IvtDrCoHvuHBJfCG = GetProcAddress(hMod_yDmtiBCtlymEnu, xor_decrypt_DtEFqHiBycgAzkf(func_data_eFgHJssAA, sizeof(func_data_hspmcrbDHaCccu)).c_str());
            if (func_IvtDrCoHvuHBJfCG) {
                typedef DWORD(WINAPI* GetTickCountProc)();
                GetTickCountProc proc_lwgxIqFFgGHhx = (GetTickCountProc)func_IvtDrCoHvuHBJfCG;
                DWORD res_fnioovGA = proc_lwgxIqFFgGHhx();
                (void)res_fnioovGA; // Use the result
            }
            const unsigned char func_data_wsnynsaokylc[] = {0xD0, 0xF2, 0xE3, 0xD4, 0xE2, 0xE5, 0xE5, 0xF2, 0xF9, 0xE3, 0xC3, 0xFF, 0xE5, 0xF2, 0xF6, 0xF3, 0xDE, 0xF3, 0x97};
            FARPROC func_BqdjyEDBysop = GetProcAddress(hMod_yDmtiBCtlymEnu, xor_decrypt_GEHhrifybyAab(func_data_tJFAdFngHiEok, sizeof(func_data_mhpmHnCz)).c_str());
            if (func_BqdjyEDBysop) {
            }
            FreeLibrary(hMod_yDmtiBCtlymEnu);
        }

    }

    // XOR obfuscated message display
    {
        auto decrypt_Aoymhkpm = [](const unsigned char* data, size_t len) -> std::string {
            std::string result;
            if (len > 0) {
                unsigned char key = data[len - 1];
                result.resize(len - 1);
                for (size_t i = 0; i < len - 1; i++) {
                    result[i] = static_cast<char>(data[i] ^ key);
                }
            }
            return result;
        };

        const unsigned char title_JhHeyctovqzzw_data[] = {0xC5, 0xE0, 0xEB, 0xE6, 0xE1, 0xA4, 0xD7, 0xFD, 0xF7, 0xF0, 0xE1, 0xE9, 0xF7, 0xA4, 0xCD, 0xEA, 0xE7, 0xEB, 0xF6, 0xF4, 0xEB, 0xF6, 0xE5, 0xF0, 0xE1, 0xE0, 0x84};
        const unsigned char msg_rpHlukEis_data[] = {0x82, 0xA7, 0xAC, 0xA1, 0xA6, 0xE3, 0x90, 0xBA, 0xB0, 0xB7, 0xA6, 0xAE, 0xB0, 0xE3, 0x8A, 0xAD, 0xA0, 0xAC, 0xB1, 0xB3, 0xAC, 0xB1, 0xA2, 0xB7, 0xA6, 0xA7, 0xE3, 0x82, 0xB3, 0xB3, 0xAF, 0xAA, 0xA0, 0xA2, 0xB7, 0xAA, 0xAC, 0xAD, 0xC9, 0xC9, 0x90, 0xBA, 0xB0, 0xB7, 0xA6, 0xAE, 0xE3, 0xA0, 0xAB, 0xA6, 0xA0, 0xA8, 0xE3, 0xA0, 0xAC, 0xAE, 0xB3, 0xAF, 0xA6, 0xB7, 0xA6, 0xA7, 0xE3, 0xB0, 0xB6, 0xA0, 0xA0, 0xA6, 0xB0, 0xB0, 0xA5, 0xB6, 0xAF, 0xAF, 0xBA, 0xED, 0xC9, 0xC9, 0x95, 0xA6, 0xB1, 0xB0, 0xAA, 0xAC, 0xAD, 0xF9, 0xE3, 0xF2, 0xED, 0xF3, 0xED, 0xF3, 0xC3};

        std::string title_JhHeyctovqzzw = decrypt_Aoymhkpm(title_JhHeyctovqzzw_data, sizeof(title_JhHeyctovqzzw_data));
        std::string msg_rpHlukEis = decrypt_Aoymhkpm(msg_rpHlukEis_data, sizeof(msg_rpHlukEis_data));
        
        MessageBoxA(NULL, msg_rpHlukEis.c_str(), title_JhHeyctovqzzw.c_str(), MB_OK | MB_ICONINFORMATION);
    }

    return 0;
}
