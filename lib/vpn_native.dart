import 'dart:ffi';
import 'dart:io' show Platform;
import 'package:ffi/ffi.dart';

typedef ConnectVpnFunc = Void Function(Pointer<Utf8>, Int32, Pointer<Utf8>, Pointer<Utf8>, Int32);
typedef ConnectVpnFuncDart = void Function(Pointer<Utf8>, int, Pointer<Utf8>, Pointer<Utf8>, int);

typedef DisconnectVpnFunc = Void Function();
typedef DisconnectVpnFuncDart = void Function();

typedef VpnStartFunc = Void Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Int32, Pointer<Utf8>, Int32);
typedef VpnStartFuncDart = void Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, int, Pointer<Utf8>, int);

typedef VpnStopFunc = Void Function(Int32);
typedef VpnStopFuncDart = void Function(int);

class VpnNative {
  late final DynamicLibrary _lib;

  VpnNative() {
    if (Platform.isWindows) {
      _lib = DynamicLibrary.process();
    } else {
      throw UnsupportedError('Unsupported platform');
    }
  }

  late final ConnectVpnFuncDart connectVpn = _lib
      .lookup<NativeFunction<ConnectVpnFunc>>('connectVpn')
      .asFunction<ConnectVpnFuncDart>();

  late final DisconnectVpnFuncDart disconnectVpn = _lib
      .lookup<NativeFunction<DisconnectVpnFunc>>('disconnectVpn')
      .asFunction<DisconnectVpnFuncDart>();

  late final VpnStartFuncDart vpnStart = _lib
      .lookup<NativeFunction<VpnStartFunc>>('vpnStart')
      .asFunction<VpnStartFuncDart>();

  late final VpnStopFuncDart vpnStop = _lib
      .lookup<NativeFunction<VpnStopFunc>>('vpnStop')
      .asFunction<VpnStopFuncDart>();
}
