#pragma once
#include <string>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include "nlohmann/json.hpp"
#include "logger.hpp"

namespace Trans {

    class Translator {
        std::unordered_map<std::string, std::string> _map;
    public:
        void load() {
            namespace fs = std::filesystem;
            // Same root resolution as settings_json.hpp
            const auto root = fs::path(REL::Module::get().filename()).parent_path();
            auto translationDir = root / "Data" / "SKSE" / "Plugins" / PRODUCT_NAME / "Translation";

            fs::path chosen;
            std::error_code ec;
            if (fs::exists(translationDir, ec) && fs::is_directory(translationDir, ec)) {
                for (const auto& entry : fs::directory_iterator(translationDir, ec)) {
                    if (entry.path().extension() == ".json") {
                        chosen = entry.path();
                        break;
                    }
                }
            }

            if (chosen.empty()) {
                logger::warn("[Trans] No translation file found in {}", translationDir.string());
                return;
            }

            try {
                std::ifstream in(chosen, std::ios::binary);
                // ignore_comments=true handles /* */ and // in the JSONC translation file
                auto j = nlohmann::json::parse(in, nullptr, true, true);
                for (auto& [k, v] : j.items()) {
                    if (v.is_string())
                        _map[k] = v.get<std::string>();
                }
                logger::info("[Trans] Loaded {} translation keys from {}",
                    _map.size(), chosen.string());
            }
            catch (const std::exception& e) {
                logger::error("[Trans] Failed to load translation: {}", e.what());
            }
        }

        std::string tr(const char* key) const {
            auto it = _map.find(key);
            return (it != _map.end()) ? it->second : key;
        }

        std::string tr(const std::string& key) const {
            auto it = _map.find(key);
            return (it != _map.end()) ? it->second : key;
        }

        // Used for plural forms: replaces {n} with count
        std::string tr(const char* key, int count) const {
            std::string s = tr(key);
            auto pos = s.find("{n}");
            if (pos != std::string::npos)
                s.replace(pos, 3, std::to_string(count));
            return s;
        }

        std::string tr(const std::string& key, int count) const {
            return tr(key.c_str(), count);
        }
    };

    inline Translator& GetTranslator() {
        static Translator t;
        return t;
    }

    inline std::string Tr(const char* key)               { return GetTranslator().tr(key); }
    inline std::string Tr(const std::string& key)        { return GetTranslator().tr(key); }
    inline std::string Tr(const char* key, int count)    { return GetTranslator().tr(key, count); }
    inline std::string Tr(const std::string& key, int count) { return GetTranslator().tr(key, count); }
}
