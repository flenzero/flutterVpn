import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'VPN Manager',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'VPN Manager Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> with WidgetsBindingObserver {
  static const platform = MethodChannel('com.example.vpn');

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stopVpn(); // Ensure VPN is stopped when the widget is disposed
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.detached) {
      _stopVpn(); // Stop VPN when app is closed or detached
    }
  }

  void _startVpn() async {
    try {
      final int result = await platform.invokeMethod('vpnStart', {
        'tunId': '6ec3cb9-ff85-41c5-89ba-0a0eca838568',
        'uuid': '76ec3cb9-ff85-41c5-89ba-0a0eca838568',
        'host': '113.240.113.70',
        'port': 62001,
        'method': 'chacha20-ietf-poly1305',
        'global': true,
      });
      if (result == 0) {
        print('VPN started successfully');
      } else {
        print('Failed to start VPN with code: $result');
      }
    } on PlatformException catch (e) {
      print('Failed to start VPN: ${e.message}');
      print('Error Code: ${e.code}');
      print('Error Details: ${e.details}');
    }
  }

  void _stopVpn() async {
    try {
      final int result = await platform.invokeMethod('vpnStop');
      if (result == 0) {
        print('VPN stopped successfully');
      } else {
        print('Failed to stop VPN with code: $result');
      }
    } on PlatformException catch (e) {
      print('Failed to stop VPN: ${e.message}');
      print('Error Code: ${e.code}');
      print('Error Details: ${e.details}');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            ElevatedButton(
              onPressed: _startVpn,
              child: Text('Start VPN'),
            ),
            SizedBox(height: 20),
            ElevatedButton(
              onPressed: _stopVpn,
              child: Text('Stop VPN'),
            ),
          ],
        ),
      ),
    );
  }
}
