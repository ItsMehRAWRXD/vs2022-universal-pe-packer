// VS2022 Menu Encryptor - Android JNI Implementation
// Native C++ implementation for Android

#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <fstream>

#define LOG_TAG "VS2022Encryptor"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Simple XOR encryption for demonstration
void xorEncrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= key[i % key.size()];
    }
}

extern "C" {

JNIEXPORT void JNICALL
Java_com_itsmehrawrxd_vs2022encryptor_VS2022MenuEncryptorActivity_initializeNative(
    JNIEnv* env, jobject /* this */) {
    
    LOGI("Native library initialized");
    
    // Anti-debugging
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        LOGI("Debugger detected!");
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_itsmehrawrxd_vs2022encryptor_VS2022MenuEncryptorActivity_encryptDataNative(
    JNIEnv* env, jobject /* this */, jbyteArray data) {
    
    // Get data from Java
    jsize len = env->GetArrayLength(data);
    std::vector<uint8_t> inputData(len);
    env->GetByteArrayRegion(data, 0, len, reinterpret_cast<jbyte*>(inputData.data()));
    
    // Generate key
    std::vector<uint8_t> key(32);
    for (int i = 0; i < 32; i++) {
        key[i] = rand() % 256;
    }
    
    // Encrypt
    xorEncrypt(inputData, key);
    
    // Return encrypted data
    jbyteArray result = env->NewByteArray(inputData.size());
    env->SetByteArrayRegion(result, 0, inputData.size(), 
                           reinterpret_cast<jbyte*>(inputData.data()));
    
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_itsmehrawrxd_vs2022encryptor_VS2022MenuEncryptorActivity_decryptDataNative(
    JNIEnv* env, jobject /* this */, jbyteArray data) {
    
    // Similar to encrypt (XOR is symmetric)
    return Java_com_itsmehrawrxd_vs2022encryptor_VS2022MenuEncryptorActivity_encryptDataNative(
        env, nullptr, data);
}

JNIEXPORT jboolean JNICALL
Java_com_itsmehrawrxd_vs2022encryptor_VS2022MenuEncryptorActivity_checkRootNative(
    JNIEnv* env, jobject /* this */) {
    
    // Check for su binary
    const char* paths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/su/bin/su"
    };
    
    for (const char* path : paths) {
        if (access(path, F_OK) == 0) {
            LOGI("Root detected: %s exists", path);
            return JNI_TRUE;
        }
    }
    
    // Check for root apps
    DIR* dir = opendir("/data/data");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string name(entry->d_name);
            if (name.find("supersu") != std::string::npos ||
                name.find("superuser") != std::string::npos ||
                name.find("magisk") != std::string::npos) {
                closedir(dir);
                LOGI("Root app detected: %s", name.c_str());
                return JNI_TRUE;
            }
        }
        closedir(dir);
    }
    
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_itsmehrawrxd_vs2022encryptor_VS2022MenuEncryptorActivity_checkDebuggerNative(
    JNIEnv* env, jobject /* this */) {
    
    // Check TracerPid in /proc/self/status
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") == 0) {
            int pid = std::stoi(line.substr(10));
            if (pid != 0) {
                LOGI("Debugger detected with PID: %d", pid);
                return JNI_TRUE;
            }
            break;
        }
    }
    
    // Check for common debugging ports
    std::ifstream tcp("/proc/net/tcp");
    while (std::getline(tcp, line)) {
        // Check for JDWP default port (8700)
        if (line.find(":21FC") != std::string::npos) {  // 8700 in hex
            LOGI("JDWP port detected");
            return JNI_TRUE;
        }
    }
    
    return JNI_FALSE;
}

// String obfuscation
std::string deobfuscate(const char* str) {
    std::string result(str);
    for (char& c : result) {
        c ^= 0x5A;  // Simple XOR obfuscation
    }
    return result;
}

// JNI_OnLoad for additional security
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    
    LOGI("JNI_OnLoad called");
    
    // Additional anti-tampering checks could go here
    
    return JNI_VERSION_1_6;
}

} // extern "C"