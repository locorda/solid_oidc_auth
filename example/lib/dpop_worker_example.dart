/// Example: DPoP Token Generation in Dart Isolates
///
/// Demonstrates offloading DPoP token generation to worker isolates.
///
/// **Note:** This is a demonstration example showing the worker thread pattern.
/// It cannot be run standalone as it requires a complete Flutter application
/// with proper UI for OIDC authentication (browser redirects, etc.).
/// Use the patterns shown here in your own Flutter app after authentication
/// has been successfully completed on the main thread.

import 'dart:isolate';
// For the "main" side of this example
import 'package:solid_oidc_auth/solid_oidc_auth.dart' show SolidOidcAuth;
// In the real pure worker.dart file, you must not import solid_auth.dart directly
// to avoid flutter dependencies. Instead, import only the necessary parts:
import 'package:solid_oidc_auth/worker.dart';

// Simple message passing between main and worker
class _WorkerMessage {
  final SendPort sendPort;
  final Map<String, dynamic> credentials;
  final String url;
  final String method;

  _WorkerMessage(this.sendPort, this.credentials, this.url, this.method);
}

/// Worker function that generates DPoP token
void _workerFunction(_WorkerMessage msg) {
  try {
    final credentials = DpopCredentials.fromJson(msg.credentials);
    final dpop = credentials.generateDpopToken(
      url: msg.url,
      method: msg.method,
    );
    // Send back as Map (serializable)
    msg.sendPort.send({
      'success': true,
      'dpopToken': dpop.dpopToken,
      'accessToken': dpop.accessToken,
    });
  } catch (e) {
    msg.sendPort.send({'success': false, 'error': e.toString()});
  }
}

/// Helper to generate DPoP in isolate
Future<DPoP> generateDpopInIsolate(
  DpopCredentials credentials,
  String url,
  String method,
) async {
  final receivePort = ReceivePort();
  await Isolate.spawn(
    _workerFunction,
    _WorkerMessage(receivePort.sendPort, credentials.toJson(), url, method),
  );

  final response = await receivePort.first as Map<String, dynamic>;
  receivePort.close();

  if (response['success'] == true) {
    // Reconstruct DPoP object from Map
    return DPoP(
      dpopToken: response['dpopToken'] as String,
      accessToken: response['accessToken'] as String,
    );
  } else {
    throw Exception('Worker error: ${response['error']}');
  }
}

void main() async {
  // Note: This example demonstrates the pattern but cannot run standalone.
  // In a real app, authentication happens in the UI with browser redirects.

  // Initialize and authenticate (must be on main thread)
  final solidAuth = SolidOidcAuth(
    oidcClientId: 'https://myapp.com/client-profile.jsonld',
    appUrlScheme: 'myapp',
    frontendRedirectUrl: Uri.parse('https://myapp.com/redirect.html'),
  );

  await solidAuth.init();

  // In a real app, uncomment and ensure proper OIDC redirect handling:
  // await solidAuth.authenticate('https://alice.pod.com/profile/card#me');

  // Export credentials once (after successful authentication)
  final credentials = solidAuth.exportDpopCredentials();

  // Generate DPoP tokens in parallel
  final urls = [
    'https://alice.pod.com/profile/card',
    'https://alice.pod.com/public/',
    'https://alice.pod.com/private/',
  ];

  final dpopTokens = await Future.wait(
    urls.map((url) => generateDpopInIsolate(credentials, url, 'GET')),
  );

  print('Generated ${dpopTokens.length} DPoP tokens in parallel');

  // Alternative: Simple compute() approach
  // Top-level function required for compute()
  // Map<String, String> _computeDpop(Map<String, dynamic> params) {
  //   final creds = DpopCredentials.fromJson(params['credentials']);
  //   final dpop = creds.generateDpopToken(
  //     url: params['url'] as String,
  //     method: params['method'] as String,
  //   );
  //   return {'dpopToken': dpop.dpopToken, 'accessToken': dpop.accessToken};
  // }
  //
  // final result = await compute(_computeDpop, {
  //   'credentials': credentials.toJson(),
  //   'url': 'https://alice.pod.com/data/',
  //   'method': 'GET',
  // });
  // final dpop = DPoP(
  //   dpopToken: result['dpopToken']!,
  //   accessToken: result['accessToken']!,
  // );
}
