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
#include <sentry.h>  // 添加 Sentry SDK 的头文件

using json = nlohmann::json;

void initSentry() {
    sentry_options_t *options = sentry_options_new();

    // 设置 DSN
    sentry_options_set_dsn(options, "https://500e74a672cbcb2e52f9a5d5e74459c0@o4505101789102080.ingest.us.sentry.io/4507529869393920"); // 替换为您的 Sentry DSN

    // 设置运行环境
    sentry_options_set_environment(options, "production");

    // 设置版本
    sentry_options_set_release(options, "vpn_manager@1.0.0");

    // 设置采样率
    sentry_options_set_sample_rate(options, 0.5); // 采样率设置为 50%

    // 启用调试模式
    sentry_options_set_debug(options, 1);

    // 附加堆栈跟踪
    sentry_options_set_attach_stacktrace(options, 1);

    // 设置最大面包屑数
    sentry_options_set_max_breadcrumbs(options, 50);

    // 初始化 Sentry
    sentry_init(options);
}

void shutdownSentry() {
    sentry_close();
}

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

  // 初始化 Sentry
  initSentry();

  try {
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
                  
                  // 调用 Sentry 记录错误
                  std::string sentryMessage = "Error Code: " + std::to_string(errorCode) + ", Message: " + errorMessage + ", Details: " + errorDetails;
                  sentry_capture_message(sentryMessage.c_str(), SENTRY_LEVEL_ERROR);
                  
                  result->Error(std::to_string(errorCode), errorMessage, flutter::EncodableValue(errorDetails));
                }
              } else {
                result->Error("Invalid arguments", "Invalid arguments for vpnStart");
              }
            } else if (call.method_name().compare("vpnStop") == 0) {
              int stopResult = vpnStop(0);
              if (stopResult == 0) {
                result->Success(flutter::EncodableValue(0));
              } else {
                result->Error("1", "Failed to stop VPN", flutter::EncodableValue(""));
              }
            } else if (call.method_name().compare("vpnCheck") == 0) {
              bool status = vpnCheck();
              if (status) {
                result->Success(flutter::EncodableValue(true)); 
              } else {
                result->Success(flutter::EncodableValue(false)); 
              }
            } else {
              result->NotImplemented();
            }
          } catch (const VpnException& ex) {
            sentry_capture_exception(ex.what());
            result->Error(std::to_string(ex.getCode()), ex.what(), flutter::EncodableValue(nullptr));
          } catch (const std::exception& e) {
            sentry_capture_exception(e.what());
            result->Error("1", e.what(), flutter::EncodableValue(nullptr));
          }
        });

    ::MSG msg;
    while (::GetMessage(&msg, nullptr, 0, 0)) {
      ::TranslateMessage(&msg);
      ::DispatchMessage(&msg);
    }

  } catch (const std::exception &e) {
    std::cerr << "Exception caught: " << e.what() << std::endl;
    sentry_capture_exception(e.what());  // 捕获异常并记录到 Sentry
  }

  // 关闭 Sentry
  shutdownSentry();

  ::CoUninitialize();
  return EXIT_SUCCESS;
}
