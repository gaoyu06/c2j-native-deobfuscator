#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <fstream>

namespace j2c {

class TraceWriter {
public:
    static TraceWriter& instance();
    void open(const std::string& path);
    void close();
    bool is_open() const { return file_.is_open(); }

    // Writes a single JSON object (must be valid JSON without a trailing newline).
    // The writer appends '\n' itself.
    void write_line(const std::string& json);

    // Helpers for building partial JSON values
    static std::string ts_now();
    static uint64_t tid();

private:
    TraceWriter() = default;
    std::ofstream file_;
    std::mutex mu_;
};

} // namespace j2c
