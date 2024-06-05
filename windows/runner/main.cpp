#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <windows.h>
#include <memory>
#include <iostream>
#include "flutter_window.h"
#include "utils.h"
#include "vpn_manager.h"
#include <nlohmann/json.hpp> // 添加 JSON 库的包含

using json = nlohmann::json;

int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev,
                      _In_ wchar_t *command_line, _In_ int show_command) {

  SetConsoleOutputCP(CP_UTF8);

  // Attach to console when present (e.g., 'flutter run') or create a
  // new console when running with a debugger.
  if (!::AttachConsole(ATTACH_PARENT_PROCESS) && ::IsDebuggerPresent()) {
    CreateAndAttachConsole();
  }

  // Initialize COM, so that it is available for use in the library and/or
  // plugins.
  ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  flutter::DartProject project(L"data");

  std::vector<std::string> command_line_arguments = GetCommandLineArguments();
  project.set_dart_entrypoint_arguments(std::move(command_line_arguments));

  FlutterWindow window(project);
  Win32Window::Point origin(10, 10);
  Win32Window::Size size(1280, 720);
  if (!window.Create(L"vpnflutter", origin, size)) {
    return EXIT_FAILURE;
  }
  window.SetQuitOnClose(true);

  // Create a MethodChannel
  auto channel = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      window.messenger(), "com.example.vpn",
      &flutter::StandardMethodCodec::GetInstance());

  // Set the MethodCallHandler
  channel->SetMethodCallHandler(
      [](const flutter::MethodCall<flutter::EncodableValue> &call,
         std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        try {
          if (call.method_name().compare("vpnStart") == 0) {
            const auto *arguments = std::get_if<flutter::EncodableMap>(call.arguments());
            if (arguments) {
              std::string tunId = std::get<std::string>(arguments->at(flutter::EncodableValue("tunId")));
              std::string uuid = std::get<std::string>(arguments->at(flutter::EncodableValue("uuid")));
              std::string host = std::get<std::string>(arguments->at(flutter::EncodableValue("host")));
              int port = std::get<int>(arguments->at(flutter::EncodableValue("port")));
              std::string method = std::get<std::string>(arguments->at(flutter::EncodableValue("method")));
              bool global = std::get<bool>(arguments->at(flutter::EncodableValue("global")));

              auto response = vpnStart(tunId.c_str(), uuid.c_str(), host.c_str(), port, method.c_str(), global);

              // Parse the JSON response and check for errors
              json json_response = json::parse(response);
              int errorCode = json_response["errorCode"];
              if (errorCode == 0) {
                result->Success(flutter::EncodableValue(0));
              } else {
                std::string errorMessage = json_response["errorMessage"];
                std::string errorDetails = json_response["errorDetails"];
                result->Error(std::to_string(errorCode), errorMessage, flutter::EncodableValue(errorDetails));
              }
            } else {
              result->Error("Invalid arguments", "Invalid arguments for vpnStart");
            }
          } else if (call.method_name().compare("vpnStop") == 0) {
            int stopResult = vpnStop(1);
            if (stopResult == 0) {
              result->Success(flutter::EncodableValue(0));
            } else {
              result->Error("1", "Failed to stop VPN", flutter::EncodableValue(""));
            }
          } else if (call.method_name().compare("checkVpn") == 0) {
            bool status = checkVpn();
            if (status) {
              result->Success(flutter::EncodableValue(0));
            } else {
              result->Error("1", "VPN is not connected", flutter::EncodableValue(""));
            }
          } else {
            result->NotImplemented();
          }
        } catch (const VpnException& ex) {
          result->Error(std::to_string(ex.getCode()), ex.what(), flutter::EncodableValue(nullptr));
        } catch (const std::exception& e) {
          result->Error("1", e.what(), flutter::EncodableValue(nullptr));
        }
      });

  ::MSG msg;
  while (::GetMessage(&msg, nullptr, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }

  ::CoUninitialize();
  return EXIT_SUCCESS;
}
