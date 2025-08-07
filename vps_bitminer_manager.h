#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <functional>
#include <regex>

// VPS BitMiner Management System
namespace VPSBitMiner {

// Core data structures
struct VPSConfig {
    std::string id;
    std::string name;
    std::string ip_address;
    int ssh_port = 22;
    std::string username;
    std::string password;
    std::string ssh_key_path;
    std::string country;
    std::string provider; // AWS, DigitalOcean, Vultr, etc.
    bool is_active = true;
    bool is_proxy_enabled = false;
    int proxy_port = 1080;
    std::string proxy_type = "SOCKS5"; // HTTP, SOCKS4, SOCKS5
    std::chrono::system_clock::time_point last_ping;
    int ping_latency = 0;
    std::vector<std::string> assigned_miners;
    double cpu_usage = 0.0;
    double memory_usage = 0.0;
    double disk_usage = 0.0;
    std::string os_info;
    std::chrono::system_clock::time_point created;
};

struct MinerConfig {
    std::string id;
    std::string name;
    std::string coin_type; // BTC, ETH, XMR, etc.
    std::string pool_url;
    std::string wallet_address;
    std::string mining_algorithm; // SHA256, Ethash, RandomX, etc.
    std::string miner_software; // xmrig, t-rex, gminer, etc.
    std::string assigned_vps_id;
    bool is_active = false;
    int thread_count = 0;
    double hash_rate = 0.0;
    double power_consumption = 0.0;
    std::chrono::system_clock::time_point last_update;
    std::map<std::string, std::string> extra_parameters;
    bool stealth_mode = true;
    int cpu_limit_percent = 80;
    bool auto_restart = true;
    std::string status = "Stopped"; // Stopped, Running, Error, Updating
};

struct PoolConfig {
    std::string id;
    std::string name;
    std::string url;
    std::string coin_type;
    std::string algorithm;
    int port;
    bool ssl_enabled = false;
    double fee_percent = 1.0;
    std::string region;
    int priority = 1; // 1 = primary, 2 = backup, etc.
    bool is_active = true;
    std::chrono::system_clock::time_point last_check;
    int response_time = 0;
    double estimated_profit = 0.0;
};

struct WalletConfig {
    std::string id;
    std::string coin_type;
    std::string address;
    std::string label;
    double balance = 0.0;
    double pending_balance = 0.0;
    std::chrono::system_clock::time_point last_updated;
    bool is_primary = false;
    std::string exchange_name; // For exchange wallets
};

struct MiningStats {
    std::string miner_id;
    std::string vps_id;
    double current_hash_rate = 0.0;
    double average_hash_rate = 0.0;
    int shares_submitted = 0;
    int shares_accepted = 0;
    int shares_rejected = 0;
    double uptime_hours = 0.0;
    double estimated_daily_profit = 0.0;
    std::chrono::system_clock::time_point last_share;
    std::string pool_response_time;
    std::vector<std::pair<std::chrono::system_clock::time_point, double>> hash_rate_history;
};

struct ProxyStats {
    std::string vps_id;
    int active_connections = 0;
    uint64_t bytes_transferred = 0;
    uint64_t total_connections = 0;
    std::chrono::system_clock::time_point last_activity;
    std::vector<std::string> connected_clients;
    double bandwidth_usage_mbps = 0.0;
};

// Main VPS BitMiner Manager Class
class VPSBitMinerManager {
private:
    std::vector<VPSConfig> vps_servers;
    std::vector<MinerConfig> miners;
    std::vector<PoolConfig> pools;
    std::vector<WalletConfig> wallets;
    std::map<std::string, MiningStats> mining_statistics;
    std::map<std::string, ProxyStats> proxy_statistics;
    
    std::mutex data_mutex;
    std::atomic<bool> monitoring_active{false};
    std::thread monitoring_thread;
    std::mt19937 rng;
    
    // Configuration limits
    std::atomic<int> max_vps_servers{50};
    std::atomic<int> max_miners{200};
    std::atomic<int> max_pools{20};
    std::atomic<int> max_wallets{10};
    
public:
    VPSBitMinerManager() : rng(std::chrono::steady_clock::now().time_since_epoch().count()) {}
    
    ~VPSBitMinerManager() {
        stop_monitoring();
    }
    
    // ========================================
    // VPS MANAGEMENT
    // ========================================
    
    std::string add_vps_server(const std::string& name, const std::string& ip, 
                              const std::string& username, const std::string& password,
                              const std::string& country = "", const std::string& provider = "") {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        if (vps_servers.size() >= max_vps_servers.load()) {
            throw std::runtime_error("Maximum VPS servers reached: " + std::to_string(max_vps_servers.load()));
        }
        
        VPSConfig vps;
        vps.id = generate_unique_id("vps_");
        vps.name = name;
        vps.ip_address = ip;
        vps.username = username;
        vps.password = password;
        vps.country = country;
        vps.provider = provider;
        vps.created = std::chrono::system_clock::now();
        vps.last_ping = vps.created;
        
        vps_servers.push_back(vps);
        
        std::cout << "✅ Added VPS server: " << vps.name << " (" << vps.ip_address << ")" << std::endl;
        return vps.id;
    }
    
    bool enable_vps_proxy(const std::string& vps_id, int proxy_port = 1080, 
                         const std::string& proxy_type = "SOCKS5") {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = find_vps_by_id(vps_id);
        if (it != vps_servers.end()) {
            it->is_proxy_enabled = true;
            it->proxy_port = proxy_port;
            it->proxy_type = proxy_type;
            
            // Deploy proxy software to VPS
            deploy_proxy_to_vps(*it);
            
            std::cout << "✅ Enabled proxy on VPS: " << it->name << " (" << proxy_type << ":" << proxy_port << ")" << std::endl;
            return true;
        }
        return false;
    }
    
    bool disable_vps_proxy(const std::string& vps_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = find_vps_by_id(vps_id);
        if (it != vps_servers.end()) {
            it->is_proxy_enabled = false;
            
            // Remove proxy software from VPS
            remove_proxy_from_vps(*it);
            
            std::cout << "✅ Disabled proxy on VPS: " << it->name << std::endl;
            return true;
        }
        return false;
    }
    
    std::vector<VPSConfig> get_proxy_enabled_vps() {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::vector<VPSConfig> proxy_vps;
        
        std::copy_if(vps_servers.begin(), vps_servers.end(), std::back_inserter(proxy_vps),
            [](const VPSConfig& vps) { return vps.is_proxy_enabled && vps.is_active; });
        
        return proxy_vps;
    }
    
    bool ping_vps(const std::string& vps_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = find_vps_by_id(vps_id);
        if (it != vps_servers.end()) {
            auto start_time = std::chrono::high_resolution_clock::now();
            
            // Simulate ping (in real implementation, use actual ping/SSH)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            
            it->ping_latency = static_cast<int>(duration.count());
            it->last_ping = std::chrono::system_clock::now();
            
            std::cout << "🏓 VPS " << it->name << " ping: " << it->ping_latency << "ms" << std::endl;
            return true;
        }
        return false;
    }
    
    bool update_vps_stats(const std::string& vps_id, double cpu, double memory, double disk) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = find_vps_by_id(vps_id);
        if (it != vps_servers.end()) {
            it->cpu_usage = cpu;
            it->memory_usage = memory;
            it->disk_usage = disk;
            return true;
        }
        return false;
    }
    
    // ========================================
    // MINER CONFIGURATION
    // ========================================
    
    std::string create_miner(const std::string& name, const std::string& coin_type,
                            const std::string& pool_url, const std::string& wallet_address) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        if (miners.size() >= max_miners.load()) {
            throw std::runtime_error("Maximum miners reached: " + std::to_string(max_miners.load()));
        }
        
        MinerConfig miner;
        miner.id = generate_unique_id("miner_");
        miner.name = name;
        miner.coin_type = coin_type;
        miner.pool_url = pool_url;
        miner.wallet_address = wallet_address;
        miner.mining_algorithm = get_algorithm_for_coin(coin_type);
        miner.miner_software = get_recommended_software(coin_type);
        miner.last_update = std::chrono::system_clock::now();
        
        miners.push_back(miner);
        
        std::cout << "✅ Created miner: " << miner.name << " (" << coin_type << ")" << std::endl;
        return miner.id;
    }
    
    bool assign_miner_to_vps(const std::string& miner_id, const std::string& vps_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto miner_it = find_miner_by_id(miner_id);
        auto vps_it = find_vps_by_id(vps_id);
        
        if (miner_it != miners.end() && vps_it != vps_servers.end()) {
            miner_it->assigned_vps_id = vps_id;
            vps_it->assigned_miners.push_back(miner_id);
            
            std::cout << "✅ Assigned miner " << miner_it->name << " to VPS " << vps_it->name << std::endl;
            return true;
        }
        return false;
    }
    
    bool start_miner(const std::string& miner_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto miner_it = find_miner_by_id(miner_id);
        if (miner_it == miners.end() || miner_it->assigned_vps_id.empty()) {
            return false;
        }
        
        auto vps_it = find_vps_by_id(miner_it->assigned_vps_id);
        if (vps_it == vps_servers.end() || !vps_it->is_active) {
            return false;
        }
        
        // Deploy and start miner on VPS
        bool success = deploy_miner_to_vps(*miner_it, *vps_it);
        if (success) {
            miner_it->is_active = true;
            miner_it->status = "Running";
            miner_it->last_update = std::chrono::system_clock::now();
            
            std::cout << "✅ Started miner: " << miner_it->name << " on VPS " << vps_it->name << std::endl;
        }
        
        return success;
    }
    
    bool stop_miner(const std::string& miner_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto miner_it = find_miner_by_id(miner_id);
        if (miner_it == miners.end()) {
            return false;
        }
        
        if (!miner_it->assigned_vps_id.empty()) {
            auto vps_it = find_vps_by_id(miner_it->assigned_vps_id);
            if (vps_it != vps_servers.end()) {
                stop_miner_on_vps(*miner_it, *vps_it);
            }
        }
        
        miner_it->is_active = false;
        miner_it->status = "Stopped";
        miner_it->last_update = std::chrono::system_clock::now();
        
        std::cout << "🛑 Stopped miner: " << miner_it->name << std::endl;
        return true;
    }
    
    bool update_miner_config(const std::string& miner_id, const std::string& pool_url,
                            const std::string& wallet_address, int thread_count = 0,
                            int cpu_limit = 80) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto miner_it = find_miner_by_id(miner_id);
        if (miner_it == miners.end()) {
            return false;
        }
        
        bool was_running = miner_it->is_active;
        
        // Stop miner if running
        if (was_running) {
            stop_miner(miner_id);
        }
        
        // Update configuration
        miner_it->pool_url = pool_url;
        miner_it->wallet_address = wallet_address;
        miner_it->thread_count = thread_count;
        miner_it->cpu_limit_percent = cpu_limit;
        miner_it->last_update = std::chrono::system_clock::now();
        
        // Restart if it was running
        if (was_running) {
            start_miner(miner_id);
        }
        
        std::cout << "✅ Updated miner config: " << miner_it->name << std::endl;
        return true;
    }
    
    // ========================================
    // POOL MANAGEMENT
    // ========================================
    
    std::string add_pool(const std::string& name, const std::string& url, 
                        const std::string& coin_type, int port, bool ssl_enabled = false) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        if (pools.size() >= max_pools.load()) {
            throw std::runtime_error("Maximum pools reached: " + std::to_string(max_pools.load()));
        }
        
        PoolConfig pool;
        pool.id = generate_unique_id("pool_");
        pool.name = name;
        pool.url = url;
        pool.coin_type = coin_type;
        pool.port = port;
        pool.ssl_enabled = ssl_enabled;
        pool.algorithm = get_algorithm_for_coin(coin_type);
        pool.last_check = std::chrono::system_clock::now();
        
        pools.push_back(pool);
        
        std::cout << "✅ Added pool: " << pool.name << " (" << pool.url << ":" << pool.port << ")" << std::endl;
        return pool.id;
    }
    
    std::vector<PoolConfig> get_pools_for_coin(const std::string& coin_type) {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::vector<PoolConfig> matching_pools;
        
        std::copy_if(pools.begin(), pools.end(), std::back_inserter(matching_pools),
            [&coin_type](const PoolConfig& pool) { 
                return pool.coin_type == coin_type && pool.is_active; 
            });
        
        // Sort by priority
        std::sort(matching_pools.begin(), matching_pools.end(),
            [](const PoolConfig& a, const PoolConfig& b) { return a.priority < b.priority; });
        
        return matching_pools;
    }
    
    bool check_pool_status(const std::string& pool_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(pools.begin(), pools.end(),
            [&pool_id](const PoolConfig& pool) { return pool.id == pool_id; });
        
        if (it != pools.end()) {
            // Simulate pool check (in real implementation, test actual connection)
            auto start_time = std::chrono::high_resolution_clock::now();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto end_time = std::chrono::high_resolution_clock::now();
            
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            it->response_time = static_cast<int>(duration.count());
            it->last_check = std::chrono::system_clock::now();
            
            std::cout << "🌐 Pool " << it->name << " response time: " << it->response_time << "ms" << std::endl;
            return true;
        }
        return false;
    }
    
    // ========================================
    // WALLET MANAGEMENT
    // ========================================
    
    std::string add_wallet(const std::string& coin_type, const std::string& address,
                          const std::string& label = "", bool is_primary = false) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        if (wallets.size() >= max_wallets.load()) {
            throw std::runtime_error("Maximum wallets reached: " + std::to_string(max_wallets.load()));
        }
        
        WalletConfig wallet;
        wallet.id = generate_unique_id("wallet_");
        wallet.coin_type = coin_type;
        wallet.address = address;
        wallet.label = label.empty() ? (coin_type + "_Wallet") : label;
        wallet.is_primary = is_primary;
        wallet.last_updated = std::chrono::system_clock::now();
        
        wallets.push_back(wallet);
        
        std::cout << "✅ Added wallet: " << wallet.label << " (" << coin_type << ")" << std::endl;
        return wallet.id;
    }
    
    std::vector<WalletConfig> get_wallets_for_coin(const std::string& coin_type) {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::vector<WalletConfig> matching_wallets;
        
        std::copy_if(wallets.begin(), wallets.end(), std::back_inserter(matching_wallets),
            [&coin_type](const WalletConfig& wallet) { return wallet.coin_type == coin_type; });
        
        // Sort primary wallets first
        std::sort(matching_wallets.begin(), matching_wallets.end(),
            [](const WalletConfig& a, const WalletConfig& b) { return a.is_primary && !b.is_primary; });
        
        return matching_wallets;
    }
    
    bool update_wallet_balance(const std::string& wallet_id, double balance, double pending = 0.0) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(wallets.begin(), wallets.end(),
            [&wallet_id](const WalletConfig& wallet) { return wallet.id == wallet_id; });
        
        if (it != wallets.end()) {
            it->balance = balance;
            it->pending_balance = pending;
            it->last_updated = std::chrono::system_clock::now();
            return true;
        }
        return false;
    }
    
    // ========================================
    // MONITORING AND STATISTICS
    // ========================================
    
    void start_monitoring() {
        monitoring_active.store(true);
        monitoring_thread = std::thread(&VPSBitMinerManager::monitoring_loop, this);
        std::cout << "✅ Started monitoring system" << std::endl;
    }
    
    void stop_monitoring() {
        monitoring_active.store(false);
        if (monitoring_thread.joinable()) {
            monitoring_thread.join();
        }
        std::cout << "🛑 Stopped monitoring system" << std::endl;
    }
    
    MiningStats get_miner_stats(const std::string& miner_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = mining_statistics.find(miner_id);
        return (it != mining_statistics.end()) ? it->second : MiningStats{};
    }
    
    ProxyStats get_proxy_stats(const std::string& vps_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = proxy_statistics.find(vps_id);
        return (it != proxy_statistics.end()) ? it->second : ProxyStats{};
    }
    
    std::map<std::string, double> get_total_hash_rates_by_coin() {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::map<std::string, double> totals;
        
        for (const auto& miner : miners) {
            if (miner.is_active) {
                auto stats_it = mining_statistics.find(miner.id);
                if (stats_it != mining_statistics.end()) {
                    totals[miner.coin_type] += stats_it->second.current_hash_rate;
                }
            }
        }
        
        return totals;
    }
    
    double get_total_estimated_daily_profit() {
        std::lock_guard<std::mutex> lock(data_mutex);
        double total = 0.0;
        
        for (const auto& [miner_id, stats] : mining_statistics) {
            total += stats.estimated_daily_profit;
        }
        
        return total;
    }
    
    // ========================================
    // REMOTE OPERATIONS
    // ========================================
    
    bool execute_remote_command(const std::string& vps_id, const std::string& command) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto vps_it = find_vps_by_id(vps_id);
        if (vps_it == vps_servers.end()) {
            return false;
        }
        
        std::cout << "🔧 Executing on VPS " << vps_it->name << ": " << command << std::endl;
        
        // In real implementation, this would use SSH to execute the command
        // For demonstration, we'll simulate the execution
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        std::cout << "✅ Command executed successfully on VPS " << vps_it->name << std::endl;
        return true;
    }
    
    bool update_miner_remotely(const std::string& miner_id, const std::map<std::string, std::string>& config) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto miner_it = find_miner_by_id(miner_id);
        if (miner_it == miners.end() || miner_it->assigned_vps_id.empty()) {
            return false;
        }
        
        auto vps_it = find_vps_by_id(miner_it->assigned_vps_id);
        if (vps_it == vps_servers.end()) {
            return false;
        }
        
        std::cout << "🔄 Updating miner " << miner_it->name << " on VPS " << vps_it->name << std::endl;
        
        // Update configuration
        for (const auto& [key, value] : config) {
            if (key == "pool_url") miner_it->pool_url = value;
            else if (key == "wallet_address") miner_it->wallet_address = value;
            else if (key == "thread_count") miner_it->thread_count = std::stoi(value);
            else if (key == "cpu_limit") miner_it->cpu_limit_percent = std::stoi(value);
            else miner_it->extra_parameters[key] = value;
        }
        
        // Apply changes remotely
        bool success = deploy_miner_to_vps(*miner_it, *vps_it);
        if (success) {
            miner_it->last_update = std::chrono::system_clock::now();
            std::cout << "✅ Miner configuration updated remotely" << std::endl;
        }
        
        return success;
    }
    
    // ========================================
    // DASHBOARD AND REPORTING
    // ========================================
    
    void show_dashboard() {
        std::cout << "\n🖥️  VPS BitMiner Dashboard" << std::endl;
        std::cout << "============================" << std::endl;
        
        // VPS Statistics
        int active_vps = 0, proxy_enabled = 0;
        for (const auto& vps : vps_servers) {
            if (vps.is_active) active_vps++;
            if (vps.is_proxy_enabled) proxy_enabled++;
        }
        
        std::cout << "🌐 VPS Servers: " << active_vps << "/" << vps_servers.size() << " active" << std::endl;
        std::cout << "🔗 Proxy Enabled: " << proxy_enabled << " VPS servers" << std::endl;
        
        // Miner Statistics
        int active_miners = 0;
        for (const auto& miner : miners) {
            if (miner.is_active) active_miners++;
        }
        
        std::cout << "⛏️  Miners: " << active_miners << "/" << miners.size() << " running" << std::endl;
        std::cout << "🏊 Pools: " << pools.size() << " configured" << std::endl;
        std::cout << "💰 Wallets: " << wallets.size() << " configured" << std::endl;
        
        // Hash Rate Summary
        auto hash_rates = get_total_hash_rates_by_coin();
        std::cout << "\n📊 Hash Rates by Coin:" << std::endl;
        for (const auto& [coin, rate] : hash_rates) {
            std::cout << "  " << coin << ": " << format_hash_rate(rate) << std::endl;
        }
        
        // Profit Summary
        double daily_profit = get_total_estimated_daily_profit();
        std::cout << "\n💵 Estimated Daily Profit: $" << std::fixed << std::setprecision(2) << daily_profit << std::endl;
        
        // Recent Activity
        std::cout << "\n📈 Recent Activity:" << std::endl;
        show_recent_activity();
    }
    
    void generate_detailed_report(const std::string& filename) {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::ofstream file(filename);
        
        if (file.is_open()) {
            file << "=== VPS BitMiner Detailed Report ===" << std::endl;
            file << "Generated: " << get_current_timestamp() << std::endl << std::endl;
            
            // VPS Report
            file << "VPS Servers:" << std::endl;
            for (const auto& vps : vps_servers) {
                file << "  " << vps.name << " (" << vps.ip_address << ")" << std::endl;
                file << "    Status: " << (vps.is_active ? "Active" : "Inactive") << std::endl;
                file << "    Proxy: " << (vps.is_proxy_enabled ? "Enabled" : "Disabled") << std::endl;
                file << "    CPU: " << vps.cpu_usage << "%, Memory: " << vps.memory_usage << "%" << std::endl;
                file << "    Assigned Miners: " << vps.assigned_miners.size() << std::endl << std::endl;
            }
            
            // Miner Report
            file << "Miners:" << std::endl;
            for (const auto& miner : miners) {
                file << "  " << miner.name << " (" << miner.coin_type << ")" << std::endl;
                file << "    Status: " << miner.status << std::endl;
                file << "    Pool: " << miner.pool_url << std::endl;
                file << "    Wallet: " << miner.wallet_address << std::endl;
                
                auto stats_it = mining_statistics.find(miner.id);
                if (stats_it != mining_statistics.end()) {
                    file << "    Hash Rate: " << format_hash_rate(stats_it->second.current_hash_rate) << std::endl;
                    file << "    Shares: " << stats_it->second.shares_accepted << "/" 
                         << stats_it->second.shares_submitted << std::endl;
                }
                file << std::endl;
            }
            
            file.close();
            std::cout << "✅ Detailed report generated: " << filename << std::endl;
        }
    }
    
private:
    // ========================================
    // HELPER FUNCTIONS
    // ========================================
    
    std::vector<VPSConfig>::iterator find_vps_by_id(const std::string& vps_id) {
        return std::find_if(vps_servers.begin(), vps_servers.end(),
            [&vps_id](const VPSConfig& vps) { return vps.id == vps_id; });
    }
    
    std::vector<MinerConfig>::iterator find_miner_by_id(const std::string& miner_id) {
        return std::find_if(miners.begin(), miners.end(),
            [&miner_id](const MinerConfig& miner) { return miner.id == miner_id; });
    }
    
    std::string generate_unique_id(const std::string& prefix) {
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        
        std::uniform_int_distribution<> dis(1000, 9999);
        int random_suffix = dis(rng);
        
        return prefix + std::to_string(timestamp) + "_" + std::to_string(random_suffix);
    }
    
    std::string get_algorithm_for_coin(const std::string& coin_type) {
        static std::map<std::string, std::string> algo_map = {
            {"BTC", "SHA256"}, {"ETH", "Ethash"}, {"XMR", "RandomX"},
            {"LTC", "Scrypt"}, {"DOGE", "Scrypt"}, {"ZEC", "Equihash"},
            {"ETC", "Ethash"}, {"RVN", "KawPow"}
        };
        
        auto it = algo_map.find(coin_type);
        return (it != algo_map.end()) ? it->second : "Unknown";
    }
    
    std::string get_recommended_software(const std::string& coin_type) {
        static std::map<std::string, std::string> software_map = {
            {"BTC", "cgminer"}, {"ETH", "t-rex"}, {"XMR", "xmrig"},
            {"LTC", "cgminer"}, {"DOGE", "cgminer"}, {"ZEC", "gminer"},
            {"ETC", "t-rex"}, {"RVN", "t-rex"}
        };
        
        auto it = software_map.find(coin_type);
        return (it != software_map.end()) ? it->second : "custom";
    }
    
    bool deploy_proxy_to_vps(const VPSConfig& vps) {
        std::cout << "🚀 Deploying proxy to VPS: " << vps.name << std::endl;
        
        // Simulate proxy deployment
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Initialize proxy stats
        ProxyStats stats;
        stats.vps_id = vps.id;
        stats.last_activity = std::chrono::system_clock::now();
        proxy_statistics[vps.id] = stats;
        
        return true;
    }
    
    bool remove_proxy_from_vps(const VPSConfig& vps) {
        std::cout << "🗑️  Removing proxy from VPS: " << vps.name << std::endl;
        
        // Simulate proxy removal
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Remove proxy stats
        proxy_statistics.erase(vps.id);
        
        return true;
    }
    
    bool deploy_miner_to_vps(const MinerConfig& miner, const VPSConfig& vps) {
        std::cout << "🚀 Deploying miner " << miner.name << " to VPS: " << vps.name << std::endl;
        
        // Simulate miner deployment
        std::this_thread::sleep_for(std::chrono::seconds(3));
        
        // Initialize mining stats
        MiningStats stats;
        stats.miner_id = miner.id;
        stats.vps_id = vps.id;
        stats.last_share = std::chrono::system_clock::now();
        mining_statistics[miner.id] = stats;
        
        return true;
    }
    
    bool stop_miner_on_vps(const MinerConfig& miner, const VPSConfig& vps) {
        std::cout << "🛑 Stopping miner " << miner.name << " on VPS: " << vps.name << std::endl;
        
        // Simulate miner stop
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        return true;
    }
    
    void monitoring_loop() {
        while (monitoring_active.load()) {
            {
                std::lock_guard<std::mutex> lock(data_mutex);
                
                // Update mining statistics
                for (auto& [miner_id, stats] : mining_statistics) {
                    if (stats.miner_id.empty()) continue;
                    
                    // Simulate hash rate updates
                    std::uniform_real_distribution<> hash_dist(50.0, 150.0);
                    stats.current_hash_rate = hash_dist(rng);
                    
                    // Update shares
                    std::uniform_int_distribution<> share_dist(0, 10);
                    stats.shares_submitted += share_dist(rng);
                    stats.shares_accepted += share_dist(rng) * 0.98; // 98% acceptance rate
                    
                    // Calculate estimated profit
                    stats.estimated_daily_profit = stats.current_hash_rate * 0.001; // $0.001 per H/s
                    
                    // Add to history
                    auto now = std::chrono::system_clock::now();
                    stats.hash_rate_history.push_back({now, stats.current_hash_rate});
                    
                    // Keep only last 100 entries
                    if (stats.hash_rate_history.size() > 100) {
                        stats.hash_rate_history.erase(stats.hash_rate_history.begin());
                    }
                }
                
                // Update proxy statistics
                for (auto& [vps_id, stats] : proxy_statistics) {
                    std::uniform_int_distribution<> conn_dist(0, 5);
                    stats.active_connections += conn_dist(rng) - 2; // Random walk
                    stats.active_connections = std::max(0, stats.active_connections);
                    
                    std::uniform_int_distribution<> bytes_dist(1000, 10000);
                    stats.bytes_transferred += bytes_dist(rng);
                    
                    stats.bandwidth_usage_mbps = stats.active_connections * 0.5;
                }
                
                // Update VPS system stats
                for (auto& vps : vps_servers) {
                    if (vps.is_active) {
                        std::uniform_real_distribution<> usage_dist(10.0, 90.0);
                        vps.cpu_usage = usage_dist(rng);
                        vps.memory_usage = usage_dist(rng);
                        vps.disk_usage = usage_dist(rng);
                    }
                }
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }
    
    std::string format_hash_rate(double hash_rate) {
        if (hash_rate >= 1000000000) {
            return std::to_string(hash_rate / 1000000000) + " GH/s";
        } else if (hash_rate >= 1000000) {
            return std::to_string(hash_rate / 1000000) + " MH/s";
        } else if (hash_rate >= 1000) {
            return std::to_string(hash_rate / 1000) + " KH/s";
        } else {
            return std::to_string(hash_rate) + " H/s";
        }
    }
    
    std::string get_current_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        return std::string(std::ctime(&time_t));
    }
    
    void show_recent_activity() {
        auto now = std::chrono::system_clock::now();
        auto one_hour_ago = now - std::chrono::hours(1);
        
        int recent_starts = 0, recent_stops = 0;
        for (const auto& miner : miners) {
            if (miner.last_update > one_hour_ago) {
                if (miner.is_active) recent_starts++;
                else recent_stops++;
            }
        }
        
        std::cout << "  Miners started: " << recent_starts << std::endl;
        std::cout << "  Miners stopped: " << recent_stops << std::endl;
    }
};

} // namespace VPSBitMiner