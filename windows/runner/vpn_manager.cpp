#include "vpn_manager.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

int sky_port = 55655;
bool vpnStopping = false;
bool connected = false;
bool isSuspending = false;
int sslocalRetry = 0;
int tun2socksRetry = 0;
const int maxRetryAttempts = 3;
PROCESS_INFORMATION sslocal1Process;
PROCESS_INFORMATION tun2socksProcess;
json vpnConfig;

void logInfo(const std::string& message) {
    std::cout << "INFO: " << message << std::endl;
}

void logError(const std::string& message) {
    std::cerr << "ERROR: " << message << std::endl;
}

std::string getEnvVar(const std::string& var) {
    char* buffer = nullptr;
    size_t size = 0;
    _dupenv_s(&buffer, &size, var.c_str());
    std::string value;
    if (buffer) {
        value = buffer;
        free(buffer);
    }
    return value;
}

std::string getCurrentDirectory() {
    char buffer[MAX_PATH];
    DWORD size = GetCurrentDirectoryA(MAX_PATH, buffer);
    if (size > 0 && size < MAX_PATH) {
        return std::string(buffer);
    } else {
        return std::string();
    }
}

std::string generateSSLocalConfig(const std::string& netID, const std::string& ip, int port, const std::string& method, const std::string& password) {
    try {
        std::string basePath = getCurrentDirectory();
        std::string configFile = basePath + "\\sslocal.conf";
        ordered_json configJson;
        configJson["local_address"] = "0.0.0.0";
        configJson["local_port"] = sky_port;
        configJson["mode"] = "tcp_and_udp";
        configJson["outbound_bind_interface"] = netID;
        configJson["locals"] = json::array({
            {
                {"protocol", "dns"},
                {"local_address", "0.0.0.0"},
                {"local_port", 53},
                {"mode", "tcp_and_udp"},
                {"local_dns_address", "223.5.5.5"},
                {"local_dns_port", 53},
                {"remote_dns_address", "99.83.168.226"},
                {"remote_dns_port", 18888}
            }
        });
        configJson["server"] = ip;
        configJson["server_port"] = port;
        configJson["method"] = method;
        configJson["password"] = password;

        std::ofstream configFileStream(configFile);
        configFileStream << configJson.dump(-1);
        configFileStream.close();

        return configFile;
    } catch (...) {
        throw VpnException(1003, "Failed to generate SSL local config");
    }
}

std::string ConvertWCHARToString(const WCHAR* wStr) {
    int bufferLen = WideCharToMultiByte(CP_UTF8, 0, wStr, -1, NULL, 0, NULL, NULL);
    std::string str(bufferLen, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wStr, -1, &str[0], bufferLen, NULL, NULL);
    return str;
}

std::vector<std::string> getNetIDs(bool filter = true) {
    std::vector<std::string> netIds;

    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);

    if (pAdapterAddresses == nullptr) {
        throw VpnException(1002, "Error allocating memory for adapter info");
    }

    ULONG dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAdapterAddresses, &bufferSize);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterAddresses);
        pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        if (pAdapterAddresses == nullptr) {
            throw VpnException(1002, "Error allocating memory for adapter info");
        }
        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAdapterAddresses, &bufferSize);
    }

    if (dwRetVal != NO_ERROR) {
        free(pAdapterAddresses);
        throw VpnException(1003, "GetAdaptersAddresses failed");
    }

    PIP_ADAPTER_ADDRESSES pAdapter = pAdapterAddresses;
    while (pAdapter) {
        if (pAdapter->OperStatus == IfOperStatusUp) { 
            std::string adapterName = ConvertWCHARToString(pAdapter->FriendlyName);

            std::string adapterDescription = ConvertWCHARToString(pAdapter->Description);
            std::for_each(adapterDescription.begin(), adapterDescription.end(), [](char& c) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            });

            if (!filter || (adapterDescription.find("virtual") == std::string::npos &&
                            adapterDescription.find("tap") == std::string::npos &&
                            adapterDescription.find("vpn") == std::string::npos &&
                            adapterDescription.find("tun") == std::string::npos &&
                            adapterDescription.find("meta") == std::string::npos &&
                            adapterDescription.find("vethernet") == std::string::npos &&
                            adapterDescription.find("radmin") == std::string::npos)) {
                netIds.push_back(adapterName);
            }
        }

        pAdapter = pAdapter->Next;
    }

    if (pAdapterAddresses) {
        free(pAdapterAddresses);
    }

    return netIds;
}

std::string getNetID() {
    std::vector<std::string> netIds = getNetIDs();
    if (!netIds.empty()) {
        return netIds[0];
    }
    throw VpnException(1006, "Failed to get NetID");
}

int getRandomInt(int min, int max) {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    return min + std::rand() % (max - min + 1);
}

void printStringDetails(const std::string& str) {
    logInfo("String: \"" + str + "\"");
    logInfo("Length: " + std::to_string(str.length()));
    logInfo("Characters: ");
    for (char c : str) {
        logInfo(std::to_string(static_cast<int>(static_cast<unsigned char>(c))) + " ");
    }
}

bool vpnNetIDExist() {
    std::vector<std::string> netIds = getNetIDs(false);
    for (const auto& netID : netIds) {
        std::string trimmedNetID = netID;
        trimmedNetID.erase(std::remove_if(trimmedNetID.begin(), trimmedNetID.end(), [](unsigned char ch) {
            return !std::isprint(ch);
        }), trimmedNetID.end());
        // printStringDetails(trimmedNetID);
        // printStringDetails("skyline-vpn-ethernet");
        if (trimmedNetID == "skyline-vpn-ethernet") {
            return true;
        }
    }
    return false;
}

void retryOperation(const std::function<void()>& operation, int maxRetries, int delay) {
    while (maxRetries > 0) {
        try {
            operation();
            return;
        } catch (...) {
            if (--maxRetries == 0) {
                throw;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }
    }
}

void readFromPipe(HANDLE pipe) {
    DWORD bytesRead;
    CHAR buffer[4096];
    BOOL success = FALSE;

    while (true) {
        success = ReadFile(pipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
        if (!success || bytesRead == 0) break;

        buffer[bytesRead] = '\0'; // Null-terminate the string
        logInfo(buffer);
    }

    CloseHandle(pipe);
}

std::string wstringToString(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring stringToWString(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

bool startProcess(PROCESS_INFORMATION& processInfo, const std::wstring& executable, const std::vector<std::wstring>& args) {
    logInfo("Starting process: " + wstringToString(executable));

    ZeroMemory(&processInfo, sizeof(processInfo));

    std::wstring cmdLine;
    for (const auto& arg : args) {
        cmdLine += L" " + arg;
    }

    SHELLEXECUTEINFOW shExInfo = {0};
    shExInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
    shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExInfo.hwnd = NULL;
    shExInfo.lpVerb = L"runas";
    shExInfo.lpFile = executable.c_str();
    shExInfo.lpParameters = cmdLine.c_str();
    shExInfo.lpDirectory = NULL;
    shExInfo.nShow = SW_HIDE;
    shExInfo.hInstApp = NULL;

    if (!ShellExecuteExW(&shExInfo)) {
        throw VpnException(1007, "Failed to start process as administrator: " + wstringToString(executable));
    }

    processInfo.hProcess = shExInfo.hProcess;
    processInfo.dwProcessId = GetProcessId(shExInfo.hProcess);

    logInfo("Started process " + std::to_string(processInfo.dwProcessId) + " with command line: " + wstringToString(executable) + " " + wstringToString(cmdLine) + " as administrator.");
    return true;
}

void stopProcess(PROCESS_INFORMATION& processInfo) {
    if (processInfo.hProcess != NULL) {
        TerminateProcess(processInfo.hProcess, 0);
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
        processInfo.hProcess = NULL;
        processInfo.hThread = NULL;
        logInfo("Process " + std::to_string(processInfo.dwProcessId) + " terminated");
    }
    else{
        logInfo("Process " + std::to_string(processInfo.dwProcessId) + " already terminated");
    }
}

void netshCommand1() {
    PROCESS_INFORMATION processInfo;
    std::wstring executable = L"netsh";
    std::vector<std::wstring> args = { L"interface", L"ip", L"set", L"address", L"skyline-vpn-ethernet", L"static", L"10.1.88.88", L"255.255.255.255", L"10.1.88.1" };
    startProcess(processInfo, executable, args);
}

void netshCommand2() {
    PROCESS_INFORMATION processInfo;
    std::wstring executable = L"netsh";
    std::vector<std::wstring> args = { L"interface", L"ip", L"set", L"dnsservers", L"skyline-vpn-ethernet", L"static", L"address=127.0.0.1" };
    startProcess(processInfo, executable, args);
}

void monitorProcess(PROCESS_INFORMATION& processInfo, const std::function<void(int, const std::string&)>& exitHandler) {
    while (true) {
        DWORD exitCode;
        if (GetExitCodeProcess(processInfo.hProcess, &exitCode)) {
            if (exitCode != STILL_ACTIVE) {
                logInfo("Process " + std::to_string(processInfo.dwProcessId) + " exited with code " + std::to_string(exitCode));
                CloseHandle(processInfo.hProcess);
                exitHandler(exitCode, "SIGTERM");
                break;
            }
        } else {
            exitHandler(3, "LOST");
            break;
        }
        Sleep(1000);
    }
}

void startSslocal1(const std::string& ip, int port, const std::string& password, const std::string& method, const std::string& netID, bool global);
void startTun2Socks(const std::string& netID);

void deleteFile(const std::wstring& filePath) {
    std::filesystem::path path(filePath);
    if (std::filesystem::exists(path)) {
        std::filesystem::remove(path);
    }
}

void handleSslocalExit(int code, const std::string& signal, const std::string& ip, int port, const std::string& password, const std::string& method, const std::string& netID, bool global) {
    std::string basePath = getCurrentDirectory();
    std::string configFile = basePath + "\\sslocal.conf";

    if (code == 0) {
        logInfo("SSLocal1 Process terminated successfully");
        deleteFile(stringToWString(configFile));
        return;
    }

    if (code == 3 && !connected) {
        logInfo("SSLocal1 Process terminated successfully");
        deleteFile(stringToWString(configFile));
        return;
    }

    logError("SSLocal1 Process terminated with code " + std::to_string(code));

    if (connected && !isSuspending && sslocalRetry < maxRetryAttempts) {
        sslocalRetry++;
        int waitTime = 3000 * sslocalRetry;
        logInfo("Retrying startSslocal1 in " + std::to_string(waitTime) + "ms (Attempt " + std::to_string(sslocalRetry) + "/" + std::to_string(maxRetryAttempts) + ")");
        Sleep(waitTime);
        startSslocal1(ip, port, password, method, netID, global);
    } else {
        deleteFile(stringToWString(configFile));
        vpnStop(1);
    }
}

void startSslocal1(const std::string& ip, int port, const std::string& password, const std::string& method, const std::string& netID, bool global) {
    std::wstring _path = stringToWString(getCurrentDirectory());
    std::vector<std::wstring> args;

    std::wstring sslocal_config = stringToWString(generateSSLocalConfig(netID, ip, port, method, password));
    args.push_back(L"-c");
    args.push_back(sslocal_config);

    if (global) {
        std::wstring acl_config = _path + L"\\core\\bypass-lan-china.acl";
        args.push_back(L"--acl");
        args.push_back(acl_config);
    }

    if (vpnStopping) {
        return;
    }

    std::wstring execProcess = _path + L"\\core\\sslocal.exe";

    if (startProcess(sslocal1Process, execProcess, args)) {
        std::thread monitorThread(monitorProcess, std::ref(sslocal1Process), 
            std::bind(handleSslocalExit, std::placeholders::_1, std::placeholders::_2, ip, port, password, method, netID, global));
        monitorThread.detach();
    }
}

void handleTun2SocksExit(int code, const std::string& signal, const std::string& netID) {
    if (code == 0) {
        logInfo("Tun2Socks Process terminated successfully");
        return;
    }

    if (code == 3 && !connected) {
        logInfo("Tun2Socks Process terminated successfully");
        return;
    }

    logError("Tun2Socks Process terminated with code " + std::to_string(code));

    if (connected && !isSuspending && tun2socksRetry < maxRetryAttempts) {
        tun2socksRetry++;
        int waitTime = 3000 * tun2socksRetry; 
        logInfo("Retrying startTun2Socks in " + std::to_string(waitTime) + "ms (Attempt " + std::to_string(tun2socksRetry) + "/" + std::to_string(maxRetryAttempts) + ")");
        Sleep(waitTime);
        startTun2Socks(netID);
        logInfo("启动netsh命令开始\n");
        // netshCommand1();
        // netshCommand2();
        logInfo("启动netsh命令完成\n");
    } else {
        vpnStop(2);
    }
    logInfo("connect: " + std::to_string(connected) + " isSuspending: " + std::to_string(isSuspending));
}

void startTun2Socks(const std::string& netID) {
    std::wstring _path = stringToWString(getCurrentDirectory());
    std::vector<std::wstring> args;

    args.push_back(L"-device");
    args.push_back(L"skyline-vpn-ethernet");
    args.push_back(L"-proxy");
    args.push_back(L"socks5://127.0.0.1:" + std::to_wstring(sky_port));
    args.push_back(L"-interface");
    args.push_back(stringToWString(netID));

    if (vpnStopping) {
        return;
    }

    std::wstring execProcess = _path + L"\\core\\tun2socks.exe";

    if (startProcess(tun2socksProcess, execProcess, args)) {
        std::thread monitorThread(monitorProcess, std::ref(tun2socksProcess), 
            std::bind(handleTun2SocksExit, std::placeholders::_1, std::placeholders::_2, netID));
        monitorThread.detach();
    }
}


void stopSslocal1() {
    stopProcess(sslocal1Process);
}

void stopTun2socks() {
    stopProcess(tun2socksProcess);
}

std::string removeNullChars(const std::string& str) {
    std::string cleanedStr;
    for (char c : str) {
        if (c != '\0') {
            cleanedStr += c;
        }
    }
    return cleanedStr;
}

void connectVpn(const std::string& ip, int port, const std::string& uuid, const std::string& method, bool global) {
    try {
        std::string netID = getNetID();
        netID = removeNullChars(netID);
        logInfo("vpn connect start");
        logInfo("@@@ " + netID);
        vpnConfig["netID"] = netID;
        sslocalRetry = 0;
        tun2socksRetry = 0;
        sky_port = getRandomInt(5000, 60000);
        logInfo("sky_port: " + std::to_string(sky_port));
        startSslocal1(ip, port, uuid, method, netID, global);
        startTun2Socks(netID);

        try {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            retryOperation([]() { if (!vpnNetIDExist()) throw VpnException(1010, "vpn NetID not found"); }, 2, 3000);
            logInfo("netsh command start");
            // netshCommand1();
            // netshCommand2();
            logInfo("netsh command end");
        } catch (const VpnException& e) {
            logError("netsh command failed: " + std::string(e.what()));
            vpnStop(0);
            throw;
        }

        logInfo("VPN connected successfully");
    } catch (const VpnException& ) {
        throw;
    } catch (const std::exception& e) {
        throw VpnException(1011, e.what());
    }
}

void disconnectVpn() {
    try {
        stopTun2socks();
    } catch (const std::exception& e) {
        std::cerr << "Failed to stop tun2socks\n";
        std::cerr << e.what() << "\n";
    }
    try {
        stopSslocal1();
    } catch (const std::exception& e) {
        std::cerr << "Failed to stop sslocal1\n";
        std::cerr << e.what() << "\n";
    }
    sslocalRetry = 0;
    tun2socksRetry = 0;
}

// Function implementations
const char* vpnStart(const char* tunId, const char* uuid, const char* host, int port, const char* method, int global) {
    logInfo("VPN START " + std::string(host) + " " + std::to_string(global));
    static std::string response;
    if (tun2socksProcess.hProcess != NULL || sslocal1Process.hProcess != NULL) {
        logError("sub process already started");
        json resultJson;
        resultJson["errorCode"] = 1001;
        resultJson["errorMessage"] = "sub process already started";
        resultJson["errorDetails"] = "";
        response = resultJson.dump();
        return response.c_str();
    }
    vpnStopping = false;
    std::string ip;
    int errorCode = 0;
    std::string errorMessage;
    std::string errorDetails;

    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        std::cerr << "WSAStartup failed: " << wsaResult << "\n";
        errorCode = 1001;
        errorMessage = "Error parsing domain name, WSAStartup failed";
    } else {
        struct addrinfo* addrResult = NULL;
        struct addrinfo hints;
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET; // IPv4
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        // Resolve the server address and port
        int iResult = getaddrinfo(host, NULL, &hints, &addrResult);
        if (iResult != 0) {
            logError("getaddrinfo failed: " + std::to_string(iResult));
            errorCode = 1001;
            errorMessage = "Error parsing domain name";
            WSACleanup();
        } else {
            char ipStr[INET_ADDRSTRLEN];
            struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)addrResult->ai_addr;
            InetNtopA(AF_INET, &(sockaddr_ipv4->sin_addr), ipStr, INET_ADDRSTRLEN);
            ip = ipStr;
            freeaddrinfo(addrResult);
            WSACleanup();
        }
    }

    if (errorCode == 0) {
        std::string tunIdStr(tunId);
        std::string uuidStr(uuid);
        std::string hostStr(host);
        std::string methodStr(method);
        
        vpnConfig = {{"tunId", tunIdStr}, {"ip", ip}, {"uuid", uuidStr}, {"host", hostStr}, {"port", port}, {"method", methodStr}, {"global", global}};
        try {
            connectVpn(ip.c_str(), port, uuidStr.c_str(), methodStr.c_str(), global);
            connected = true;
        } catch (const VpnException& e) {
            errorCode = e.getCode();
            errorMessage = e.what();
            errorDetails = e.getDetails();
        } catch (const std::exception& e) {
            errorCode = 1012;
            errorMessage = e.what();
            errorDetails = "";
        }
    }
    std::cout << "Start end\n" << std::endl;
    json resultJson;
    resultJson["errorCode"] = errorCode;
    resultJson["errorMessage"] = errorMessage;
    resultJson["errorDetails"] = errorDetails;
    response = resultJson.dump();
    return response.c_str();
}

int vpnStop(int stopType) {
    if (stopType == 0) {
        logError("vpnStop called with first nesth failed");
    }
    if (stopType == 1) {
        logError("vpnStop called with second nesth failed");
    }
    if (stopType == 2) {
        logError("vpnStop called with tun2socks failed");
    }
    vpnStopping = true;
    connected = false;
    disconnectVpn();
    return 0;
}

bool vpnCheck() {
    return connected;
}
