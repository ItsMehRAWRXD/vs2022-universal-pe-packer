    std::string bytesToBigDecimal(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;
        ss << "0x";
        for (uint8_t byte : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }

    std::string generateUniqueVarName() {
        static int counter = 0;
        std::string prefix = "var_";
        std::string suffix = std::to_string(counter++);
        
        // Add some randomness
        std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for (int i = 0; i < 3; i++) {
            prefix += chars[rng() % chars.length()];
        }
        
        return prefix + suffix;
    }