#ifndef VPN_MANAGER_H_
#define VPN_MANAGER_H_

#include <string>
#include <exception>
#include <nlohmann/json.hpp> // 添加 JSON 库的包含

using json = nlohmann::json;


class VpnException : public std::exception {
public:
    VpnException(int code, const std::string& message, const std::string& details = "")
        : code_(code), message_(message), details_(details) {}

    int getCode() const { return code_; }
    const char* what() const noexcept override { return message_.c_str(); }
    const std::string& getDetails() const { return details_; }

private:
    int code_;
    std::string message_;
    std::string details_;
};


// Ensure that the functions are exported correctly for use with MethodChannel
extern "C" {
    __declspec(dllexport) const char* vpnStart(const char* tunId, const char* uuid, const char* host, int port, const char* method, int global);
    __declspec(dllexport) int vpnStop(int global);
    __declspec(dllexport) bool vpnCheck();
}

#endif  // VPN_MANAGER_H_
