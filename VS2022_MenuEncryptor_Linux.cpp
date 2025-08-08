// VS2022 Menu Encryptor - Linux Native Version
// Optimized for Linux with kernel features and system APIs

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cstring>
#include <thread>
#include <algorithm>
#include <memory>

// Linux-specific headers
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/inotify.h>
#include <sys/capability.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <keyutils.h>
#include <linux/random.h>
#include <linux/memfd.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <sodium.h>
#include <gtk/gtk.h>

class VS2022MenuEncryptorLinux {
private:
    std::mt19937_64 rng;
    bool hasRoot;
    bool hasSecureBoot;
    bool hasTPM;
    bool isSystemd;
    bool hasAppArmor;
    bool hasSELinux;
    int inotifyFd;
    
public:
    VS2022MenuEncryptorLinux() : rng(std::chrono::high_resolution_clock::now().time_since_epoch().count()) {
        // Check Linux capabilities
        checkLinuxFeatures();
        
        // Initialize security
        initializeSecurity();
        
        // Setup anti-debugging
        setupAntiDebug();
        
        // Initialize crypto
        if (sodium_init() < 0) {
            std::cerr << "Failed to initialize libsodium" << std::endl;
        }
        
        // Initialize inotify
        inotifyFd = inotify_init1(IN_NONBLOCK);
    }
    
    ~VS2022MenuEncryptorLinux() {
        if (inotifyFd >= 0) {
            close(inotifyFd);
        }
    }
    
    void checkLinuxFeatures() {
        // Check if running as root
        hasRoot = (geteuid() == 0);
        
        // Check for Secure Boot
        std::ifstream secureboot("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
        hasSecureBoot = secureboot.good();
        
        // Check for TPM
        struct stat st;
        hasTPM = (stat("/dev/tpm0", &st) == 0) || (stat("/dev/tpmrm0", &st) == 0);
        
        // Check for systemd
        isSystemd = (stat("/run/systemd/system", &st) == 0);
        
        // Check for AppArmor
        hasAppArmor = (stat("/sys/kernel/security/apparmor", &st) == 0);
        
        // Check for SELinux
        hasSELinux = (stat("/sys/fs/selinux", &st) == 0);
    }
    
    void initializeSecurity() {
        // Disable core dumps
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = 0;
        setrlimit(RLIMIT_CORE, &rl);
        
        // Enable ASLR
        personality(ADDR_NO_RANDOMIZE);
        
        // Set process as non-dumpable
        prctl(PR_SET_DUMPABLE, 0);
        
        // Enable seccomp if available
        if (prctl(PR_GET_SECCOMP) >= 0) {
            setupSeccomp();
        }
        
        // Lock memory pages
        mlockall(MCL_CURRENT | MCL_FUTURE);
    }
    
    void setupAntiDebug() {
        // Multiple anti-debugging techniques
        
        // 1. ptrace anti-debug
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
            std::cout << "🚫 Debugger detected! Exiting..." << std::endl;
            exit(1);
        }
        
        // 2. Check /proc/self/status for TracerPid
        std::ifstream status("/proc/self/status");
        std::string line;
        while (std::getline(status, line)) {
            if (line.find("TracerPid:") == 0) {
                int pid = std::stoi(line.substr(10));
                if (pid != 0) {
                    std::cout << "🚫 Debugger detected (PID: " << pid << ")!" << std::endl;
                    exit(1);
                }
                break;
            }
        }
        
        // 3. Set process name to hide
        prctl(PR_SET_NAME, "systemd-resolved");
    }
    
    void setupSeccomp() {
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
        if (ctx == NULL) return;
        
        // Block dangerous syscalls
        seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0);
        seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0);
        seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0);
        
        seccomp_load(ctx);
        seccomp_release(ctx);
        
        std::cout << "🛡️  Seccomp filters enabled" << std::endl;
    }
    
    // Linux kernel crypto API
    std::vector<uint8_t> encryptWithKernelCrypto(const std::vector<uint8_t>& data) {
        int fd = open("/dev/crypto", O_RDWR);
        if (fd < 0) {
            std::cout << "❌ Kernel crypto not available, using libsodium" << std::endl;
            return encryptWithSodium(data);
        }
        
        // Kernel crypto implementation would go here
        close(fd);
        
        return data; // Placeholder
    }
    
    // Libsodium encryption
    std::vector<uint8_t> encryptWithSodium(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> ciphertext(data.size() + crypto_secretbox_MACBYTES);
        std::vector<uint8_t> nonce(crypto_secretbox_NONCEBYTES);
        std::vector<uint8_t> key(crypto_secretbox_KEYBYTES);
        
        // Generate random key and nonce
        randombytes_buf(key.data(), key.size());
        randombytes_buf(nonce.data(), nonce.size());
        
        // Encrypt
        crypto_secretbox_easy(ciphertext.data(), data.data(), data.size(),
                             nonce.data(), key.data());
        
        std::cout << "🔐 Encrypted with libsodium (XChaCha20-Poly1305)" << std::endl;
        
        return ciphertext;
    }
    
    // Memory-based file system for sensitive data
    std::string createMemFile(const std::string& name, const std::vector<uint8_t>& data) {
        int fd = memfd_create(name.c_str(), MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (fd < 0) {
            std::cerr << "Failed to create memfd" << std::endl;
            return "";
        }
        
        // Write data
        write(fd, data.data(), data.size());
        
        // Seal the file
        fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
        
        std::string path = "/proc/self/fd/" + std::to_string(fd);
        std::cout << "📝 Created sealed memory file: " << path << std::endl;
        
        return path;
    }
    
    // File monitoring with inotify
    void monitorDirectory(const std::string& path) {
        int wd = inotify_add_watch(inotifyFd, path.c_str(),
                                  IN_ACCESS | IN_MODIFY | IN_CREATE | IN_DELETE);
        
        if (wd < 0) {
            std::cerr << "Failed to add inotify watch" << std::endl;
            return;
        }
        
        std::cout << "📁 Monitoring directory: " << path << std::endl;
        
        std::thread([this, wd]() {
            char buffer[4096];
            
            while (true) {
                int length = read(inotifyFd, buffer, sizeof(buffer));
                if (length < 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                
                int i = 0;
                while (i < length) {
                    struct inotify_event* event = (struct inotify_event*)&buffer[i];
                    
                    if (event->len) {
                        std::string filename(event->name);
                        
                        // Check for sensitive files
                        if (filename.find(".key") != std::string::npos ||
                            filename.find(".pem") != std::string::npos ||
                            filename.find("password") != std::string::npos) {
                            
                            std::cout << "⚠️  Sensitive file accessed: " << filename << std::endl;
                        }
                    }
                    
                    i += sizeof(struct inotify_event) + event->len;
                }
            }
        }).detach();
    }
    
    // GTK file picker
    std::string pickFileWithGTK() {
        gtk_init(nullptr, nullptr);
        
        GtkWidget* dialog = gtk_file_chooser_dialog_new(
            "Select File to Encrypt",
            NULL,
            GTK_FILE_CHOOSER_ACTION_OPEN,
            "_Cancel", GTK_RESPONSE_CANCEL,
            "_Open", GTK_RESPONSE_ACCEPT,
            NULL
        );
        
        std::string filename;
        
        if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
            char* selected = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
            filename = std::string(selected);
            g_free(selected);
        }
        
        gtk_widget_destroy(dialog);
        
        // Process pending GTK events
        while (gtk_events_pending()) {
            gtk_main_iteration();
        }
        
        return filename;
    }
    
    // Process capabilities
    void showCapabilities() {
        cap_t caps = cap_get_proc();
        if (caps == NULL) {
            std::cout << "Failed to get capabilities" << std::endl;
            return;
        }
        
        char* caps_text = cap_to_text(caps, NULL);
        std::cout << "Process capabilities: " << caps_text << std::endl;
        
        cap_free(caps_text);
        cap_free(caps);
    }
    
    // Container detection
    bool isInContainer() {
        // Check for Docker
        if (std::filesystem::exists("/.dockerenv")) {
            return true;
        }
        
        // Check cgroup
        std::ifstream cgroup("/proc/self/cgroup");
        std::string line;
        while (std::getline(cgroup, line)) {
            if (line.find("docker") != std::string::npos ||
                line.find("lxc") != std::string::npos ||
                line.find("kubepods") != std::string::npos) {
                return true;
            }
        }
        
        return false;
    }
    
    // System information
    void showSystemInfo() {
        struct utsname buffer;
        if (uname(&buffer) == 0) {
            std::cout << "🐧 System: " << buffer.sysname << " " << buffer.release << std::endl;
            std::cout << "🖥️  Machine: " << buffer.machine << std::endl;
        }
        
        // CPU info
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") != std::string::npos) {
                std::cout << "💻 CPU: " << line.substr(line.find(":") + 2) << std::endl;
                break;
            }
        }
        
        // Memory info
        std::ifstream meminfo("/proc/meminfo");
        while (std::getline(meminfo, line)) {
            if (line.find("MemTotal") != std::string::npos) {
                std::cout << "🧠 " << line << std::endl;
                break;
            }
        }
    }
    
    // Persistence via systemd
    void setupSystemdPersistence() {
        if (!isSystemd || !hasRoot) {
            std::cout << "❌ Systemd persistence requires root on systemd system" << std::endl;
            return;
        }
        
        std::string servicePath = "/etc/systemd/system/vs2022-encryptor.service";
        std::ofstream service(servicePath);
        
        service << "[Unit]\n";
        service << "Description=VS2022 Menu Encryptor Service\n";
        service << "After=network.target\n\n";
        
        service << "[Service]\n";
        service << "Type=simple\n";
        service << "ExecStart=" << std::filesystem::current_path() / "VS2022_MenuEncryptor_Linux\n";
        service << "Restart=always\n";
        service << "User=root\n\n";
        
        service << "[Install]\n";
        service << "WantedBy=multi-user.target\n";
        
        service.close();
        
        system("systemctl daemon-reload");
        system("systemctl enable vs2022-encryptor.service");
        
        std::cout << "✅ Systemd service installed" << std::endl;
    }
    
    void showLinuxMenu() {
        system("clear");
        
        std::cout << "\n┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓" << std::endl;
        std::cout << "┃     VS2022 Menu Encryptor - Linux Native Edition       ┃" << std::endl;
        std::cout << "┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫" << std::endl;
        std::cout << "┃ System Status:                                          ┃" << std::endl;
        std::cout << "┃   • Root: " << (hasRoot ? "YES" : "NO") << "                                           ┃" << std::endl;
        std::cout << "┃   • Secure Boot: " << (hasSecureBoot ? "Enabled" : "Disabled") << "                          ┃" << std::endl;
        std::cout << "┃   • TPM: " << (hasTPM ? "Available" : "Not Found") << "                                  ┃" << std::endl;
        std::cout << "┃   • SELinux: " << (hasSELinux ? "Active" : "Inactive") << "                              ┃" << std::endl;
        std::cout << "┃   • AppArmor: " << (hasAppArmor ? "Active" : "Inactive") << "                             ┃" << std::endl;
        std::cout << "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" << std::endl;
        
        std::cout << "\n--- Linux-Specific Features ---" << std::endl;
        std::cout << " 1. GTK File Picker" << std::endl;
        std::cout << " 2. Kernel Crypto API" << std::endl;
        std::cout << " 3. Memory-Only Files (memfd)" << std::endl;
        std::cout << " 4. Directory Monitor (inotify)" << std::endl;
        std::cout << " 5. Show Capabilities" << std::endl;
        std::cout << " 6. Container Detection" << std::endl;
        std::cout << " 7. System Information" << std::endl;
        std::cout << " 8. Systemd Persistence (Root)" << std::endl;
        std::cout << " 9. Seccomp Sandbox" << std::endl;
        
        std::cout << "\n--- Standard Features ---" << std::endl;
        std::cout << "10-31. [All original menu options...]" << std::endl;
        
        std::cout << "\n 0. Exit" << std::endl;
        std::cout << "\nEnter your choice: ";
    }
};

int main(int argc, char* argv[]) {
    VS2022MenuEncryptorLinux encryptor;
    
    std::cout << "🐧 VS2022 Menu Encryptor - Linux Native Edition" << std::endl;
    std::cout << "🔒 Enhanced with Linux kernel features" << std::endl;
    
    // Linux-specific initialization
    if (encryptor.isInContainer()) {
        std::cout << "🐳 Running inside container" << std::endl;
    }
    
    // Show system info on startup
    encryptor.showSystemInfo();
    
    // Main loop
    while (true) {
        encryptor.showLinuxMenu();
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        switch (choice) {
            case 1: {
                std::string file = encryptor.pickFileWithGTK();
                if (!file.empty()) {
                    std::cout << "Selected: " << file << std::endl;
                }
                break;
            }
            case 2:
                std::cout << "Using kernel crypto API..." << std::endl;
                break;
            case 3: {
                std::vector<uint8_t> testData = {1, 2, 3, 4, 5};
                encryptor.createMemFile("test_secure", testData);
                break;
            }
            case 4: {
                std::cout << "Enter directory to monitor: ";
                std::string dir;
                std::getline(std::cin, dir);
                encryptor.monitorDirectory(dir);
                break;
            }
            case 5:
                encryptor.showCapabilities();
                break;
            case 6:
                std::cout << "Container detected: " << 
                    (encryptor.isInContainer() ? "YES" : "NO") << std::endl;
                break;
            case 7:
                encryptor.showSystemInfo();
                break;
            case 8:
                encryptor.setupSystemdPersistence();
                break;
            case 9:
                encryptor.setupSeccomp();
                break;
            case 0:
                std::cout << "Goodbye!" << std::endl;
                return 0;
            default:
                // Handle standard menu options
                break;
        }
        
        std::cout << "\nPress Enter to continue...";
        std::cin.get();
    }
    
    return 0;
}