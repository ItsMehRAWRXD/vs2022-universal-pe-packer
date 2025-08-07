    std::string bytesToBigDecimal(const std::vector<uint8_t>& bytes) {
        std::vector<uint8_t> result = {0};
        
        for (uint8_t byte : bytes) {
            int carry = 0;
            for (int i = result.size() - 1; i >= 0; i--) {
                int prod = result[i] * 256 + carry;
                result[i] = prod % 10;
                carry = prod / 10;
            }
            while (carry > 0) {
                result.insert(result.begin(), carry % 10);
                carry /= 10;
            }
            
            carry = byte;
            for (int i = result.size() - 1; i >= 0 && carry > 0; i--) {
                int sum = result[i] + carry;
                result[i] = sum % 10;
                carry = sum / 10;
            }
            while (carry > 0) {
                result.insert(result.begin(), carry % 10);
                carry /= 10;
            }
        }
        
        std::string decimal;
        for (uint8_t digit : result) {
            decimal += ('0' + digit);
        }
        return decimal.empty() ? "0" : decimal;
    }

    std::string generateUniqueVarName() {
        const std::vector<std::string> prefixes = {"var", "data", "buf", "mem", "tmp", "obj", "ptr", "val", "cfg", "sys"};
        const std::vector<std::string> middles = {"Core", "Mgr", "Proc", "Ctrl", "Hdl", "Ref", "Ctx", "Buf", "Ops", "Util"};
        const std::vector<std::string> suffixes = {"Ex", "Ptr", "Obj", "Cfg", "Mgr", "Ctx", "Buf", "Ops", "Val", "Ref"};
        
        std::string name = prefixes[rng() % prefixes.size()];
        name += middles[rng() % middles.size()];
        name += suffixes[rng() % suffixes.size()];
        name += std::to_string(rng() % 10000);
        
        return name;
    }