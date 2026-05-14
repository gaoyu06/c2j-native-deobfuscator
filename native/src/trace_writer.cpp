#include "trace_writer.hpp"

#include <chrono>
#include <thread>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace j2c {

TraceWriter& TraceWriter::instance() {
    static TraceWriter inst;
    return inst;
}

void TraceWriter::open(const std::string& path) {
    std::lock_guard<std::mutex> g(mu_);
    file_.open(path, std::ios::out | std::ios::trunc);
}

void TraceWriter::close() {
    std::lock_guard<std::mutex> g(mu_);
    if (file_.is_open()) file_.close();
}

void TraceWriter::write_line(const std::string& json) {
    std::lock_guard<std::mutex> g(mu_);
    if (!file_.is_open()) return;
    file_ << json << '\n';
}

std::string TraceWriter::ts_now() {
    auto t = std::chrono::system_clock::now().time_since_epoch();
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(t).count();
    std::ostringstream os;
    os << micros;
    return os.str();
}

uint64_t TraceWriter::tid() {
#ifdef _WIN32
    return static_cast<uint64_t>(GetCurrentThreadId());
#else
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(pthread_self()));
#endif
}

} // namespace j2c
