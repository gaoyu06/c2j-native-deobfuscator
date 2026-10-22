#pragma once
#include <algorithm>
#include <string>
#include <vector>

namespace j2c {
// Java dotted names and JVM internal names are equivalent. * spans packages.
class ClassFilter {
    std::vector<std::string> patterns_;
    static std::string normalize(std::string name) {
        const auto first = name.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return {};
        name = name.substr(first, name.find_last_not_of(" \t\r\n") - first + 1);
        if (name.size() >= 2 && name.front() == 'L' && name.back() == ';')
            name = name.substr(1, name.size() - 2);
        std::replace(name.begin(), name.end(), '.', '/');
        return name;
    }
    static bool glob(const std::string& pattern, const std::string& name) {
        size_t p = 0, n = 0, star = std::string::npos, retry = 0;
        while (n < name.size()) {
            if (p < pattern.size() && pattern[p] == name[n]) { ++p; ++n; }
            else if (p < pattern.size() && pattern[p] == '*') { star = p++; retry = n; }
            else if (star != std::string::npos) { p = star + 1; n = ++retry; }
            else return false;
        }
        while (p < pattern.size() && pattern[p] == '*') ++p;
        return p == pattern.size();
    }
public:
    void add(const std::string& list) {
        size_t start = 0;
        while (start <= list.size()) {
            size_t end = list.find(';', start);
            auto pattern = normalize(list.substr(start, end == std::string::npos ? end : end - start));
            if (!pattern.empty()) patterns_.push_back(pattern);
            if (end == std::string::npos || end == list.size()) break;
            start = end + 1;
        }
    }
    bool active() const { return !patterns_.empty(); }
    bool matches(const std::string& name) const {
        if (!active()) return true;
        const auto normalized = normalize(name);
        for (const auto& pattern : patterns_) if (glob(pattern, normalized)) return true;
        return false;
    }
};
inline ClassFilter class_filter;
} // namespace j2c
