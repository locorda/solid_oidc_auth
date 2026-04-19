/// Flutter-free entry point for DPoP token generation in worker threads/isolates.
///
/// This library provides a minimal, Flutter-independent API for generating DPoP
/// tokens from serialized credentials. It's specifically designed for use in
/// Dart isolates and web workers where Flutter dependencies are not available.
///
/// ## Purpose
///
/// The main `solid_oidc_auth` library depends on Flutter for UI components and
/// platform-specific storage. Worker threads and isolates cannot access Flutter
/// APIs, so this library provides a separate entry point that:
///
/// - Contains **zero Flutter dependencies**
/// - Exports only what's needed for DPoP token generation
/// - Can be safely imported in isolate entry points
/// - Uses only pure Dart and platform-independent cryptography
///
/// ## Usage Pattern
///
/// ```dart
/// // Main thread (can use full solid_oidc_auth library)
/// import 'package:solid_oidc_auth/solid_oidc_auth.dart';
///
/// final solidAuth = SolidOidcAuth(...);
/// await solidAuth.init();
/// await solidAuth.authenticate('https://alice.pod.com/profile/card#me');
///
/// // Export credentials for worker
/// final credentials = solidAuth.exportDpopCredentials();
///
/// // Spawn worker with serialized credentials
/// await Isolate.spawn(workerEntryPoint, credentials.toJson());
/// ```
///
/// ```dart
/// // Worker thread (uses Flutter-free worker library)
/// import 'package:solid_oidc_auth/worker.dart';
///
/// void workerEntryPoint(Map<String, dynamic> credentialsJson) {
///   // Deserialize credentials
///   final credentials = DpopCredentials.fromJson(credentialsJson);
///
///   // Generate DPoP tokens (no Flutter APIs needed)
///   final dpop = credentials.generateDpopToken(
///     url: 'https://alice.pod.com/data/',
///     method: 'GET',
///   );
///
///   // Use dpop.httpHeaders() for authenticated requests
/// }
/// ```
///
/// ## What's Exported
///
/// - [DpopCredentials]: Serializable credentials container
/// - [DPoP]: Result object containing DPoP token and access token
/// - [KeyPair]: Platform-agnostic RSA key pair representation
///
/// ## What's NOT Exported
///
/// - [SolidOidcAuth]: Main authentication class (requires Flutter)
/// - OIDC flow management (requires Flutter for browser redirects)
/// - Session persistence (requires Flutter for platform storage)
/// - Any UI or platform-specific components
///
/// ## Architecture
///
/// ```
/// ┌─────────────────────────────────────────┐
/// │         Main Thread (Flutter)           │
/// │  import 'package:solid_oidc_auth/solid_oidc_auth' │
/// │                                         │
/// │  - SolidOidcAuth (authentication)       │
/// │  - Browser redirects                    │
/// │  - Session management                   │
/// │  - exportDpopCredentials()             │
/// └─────────────────────────────────────────┘
///                      │
///                      │ Serialize credentials
///                      │ (DpopCredentials.toJson())
///                      ▼
/// ┌─────────────────────────────────────────┐
/// │       Worker Thread (Pure Dart)         │
/// │  import 'package:solid_oidc_auth/worker'     │
/// │                                         │
/// │  - DpopCredentials.fromJson()           │
/// │  - generateDpopToken()                  │
/// │  - No Flutter dependencies              │
/// └─────────────────────────────────────────┘
/// ```
///
/// ## Security Considerations
///
/// Credentials contain sensitive cryptographic material:
/// - RSA private key
/// - OAuth2 access token
///
/// While safe for intra-process transfer (isolates/workers), never:
/// - Serialize credentials to persistent storage
/// - Send credentials over the network
/// - Log credentials in plaintext
///
/// See [doc/dpop_worker_threads.md](../doc/dpop_worker_threads.md) for
/// comprehensive security guidelines.
library;

export 'src/rsa/rsa_api.dart' show KeyPair;
export 'src/oidc/dpop_credentials.dart' show DpopCredentials, DPoP;
