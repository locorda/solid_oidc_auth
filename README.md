<!-- 
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/guides/libraries/writing-package-pages). 

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-library-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/developing-packages). 
-->

# Solid OIDC Auth

[![pub package](https://img.shields.io/pub/v/solid_oidc_auth.svg)](https://pub.dev/packages/solid_oidc_auth)

A Flutter library for authenticating with [Solid pods](https://solidproject.org/) using OpenID Connect, implementing the [Solid-OIDC specification](https://solid.github.io/solid-oidc/).

This library provides a simple, reactive interface for Solid authentication that handles the complexity of OIDC flows, token management, WebID discovery, and DPoP (Demonstration of Proof-of-Possession) tokens required by Solid servers.

Built on the robust foundation of [Bdaya-Dev/oidc](https://pub.dev/packages/oidc), this package focuses specifically on Solid pod authentication while leveraging excellent, well-maintained OpenID Connect functionality.


## ✨ Features

- **🔐 Complete Solid Authentication**: Full implementation of Solid-OIDC specification
- **📱 Cross-Platform**: Works on web, mobile (iOS/Android), and desktop (macOS)
- **🔄 Reactive State Management**: Use `ValueListenable` to reactively update UI based on authentication status
- **💾 Automatic Session Restoration**: Persists authentication across app restarts
- **🛡️ DPoP Token Support**: Handles security tokens required by Solid servers
- **🌐 WebID Discovery**: Automatically discovers identity providers from WebIDs
- **🔒 Secure Token Storage**: Uses platform-appropriate secure storage mechanisms

<!-- ## Getting started

TODO: List prerequisites and provide or point to information on how to
start using the package. -->

## 🚀 Quick Start

### 1. Add to pubspec.yaml

```sh
dart pub add solid_oidc_auth
```

### 2. Create Your Client Profile

Create a `client-profile.jsonld` file and host it on HTTPS:

💡 **Hosting Tip**: Don't have a server? You can easily host this file for free using [GitHub Pages](https://pages.github.com/), [Netlify](https://www.netlify.com/), or [Vercel](https://vercel.com/). Just commit the file to your repository and enable static hosting.

```json
{
  "@context": "https://www.w3.org/ns/solid/oidc-context.jsonld",
  "client_id": "https://myapp.com/client-profile.jsonld",
  "client_name": "My Solid App",
  "application_type": "native",
  "redirect_uris": [
    "https://myapp.com/auth/callback.html",
    "com.mycompany.myapp://redirect"
  ],
  "post_logout_redirect_uris": [
    "https://myapp.com/auth/callback.html",
    "com.mycompany.myapp://logout"
  ],
  "scope": "openid webid offline_access profile",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

🚨 **CRITICAL REQUIREMENT**: The `client_id` field **must** be the exact URL where you host this document.

If you host this at `https://myapp.com/client-profile.jsonld`, then:
- The `client_id` field **must** be `"https://myapp.com/client-profile.jsonld"`
- The `oidcClientId` parameter **must** be `'https://myapp.com/client-profile.jsonld'`
- Both values **must** be identical

### 3. Initialize SolidOidcAuth

```dart
import 'package:solid_oidc_auth/solid_oidc_auth.dart';

// Initialize SolidOidcAuth with your client configuration
final solidAuth = SolidOidcAuth(
  // This URL must exactly match the "client_id" field in your client-profile.jsonld
  oidcClientId: 'https://myapp.com/client-profile.jsonld',
  appUrlScheme: 'com.mycompany.myapp',
  frontendRedirectUrl: Uri.parse('https://myapp.com/auth/callback.html'),
);

// Initialize and check for existing session
await solidAuth.init();
```

### 4. Build Reactive UI

```dart
// Build reactive UI based on authentication state
ValueListenableBuilder<bool>(
  valueListenable: solidAuth.isAuthenticatedNotifier,
  builder: (context, isAuthenticated, child) {
    if (isAuthenticated) {
      return Text('Welcome, ${solidAuth.currentWebId}!');
    } else {
      return ElevatedButton(
        onPressed: () => authenticate(),
        child: Text('Login with Solid'),
      );
    }
  },
);
```

### 5. Authenticate Users

```dart
// Authenticate with a WebID or identity provider
Future<void> authenticate() async {
  try {
    final result = await solidAuth.authenticate(
      'https://alice.solidcommunity.net/profile/card#me'
    );
    print('Authenticated as: ${result.webId}');
  } catch (e) {
    print('Authentication failed: $e');
  }
}
```

### 6. Make Authenticated API Requests

```dart
// Generate DPoP token and make authenticated request
Future<void> fetchPrivateData() async {
  // Generate DPoP token for the specific request
  final dpop = solidAuth.genDpopToken(
    'https://alice.solidcommunity.net/private/data.ttl',
    'GET'
  );

  final response = await http.get(
    Uri.parse('https://alice.solidcommunity.net/private/data.ttl'),
    headers: {
      ...dpop.httpHeaders(), // Includes Authorization and DPoP headers
      'Accept': 'text/turtle',
    },
  );

  if (response.statusCode == 200) {
    print('Private data: ${response.body}');
  }
}
```

## 📚 Comprehensive Examples

### Authentication with Additional Scopes

```dart
// Request additional scopes (must be declared in client-profile.jsonld)
final result = await solidAuth.authenticate(
  'https://alice.solidcommunity.net/profile/card#me',
  scopes: ['profile', 'email'], // Additional to required: openid, webid, offline_access
);
```

### Authenticate with Identity Provider URL

```dart
// Authenticate directly with provider (skips WebID discovery)
final result = await solidAuth.authenticate(
  'https://solidcommunity.net'
);
```

### Session Management

```dart
// Check authentication status
if (solidAuth.isAuthenticated) {
  print('User: ${solidAuth.currentWebId}');
}

// Logout user
await solidAuth.logout();

// Clean up resources
await solidAuth.dispose();
```

## ⚡ Advanced: DPoP Token Generation in Worker Threads

For performance-critical applications that need to generate many DPoP tokens without blocking the UI, `solid_oidc_auth` provides a Flutter-free entry point for use in Dart isolates and web workers.

### Why Use Worker Threads?

- **Non-blocking UI**: Offload cryptographic operations from the main thread
- **Parallel Processing**: Generate multiple DPoP tokens concurrently
- **Better Performance**: Utilize multiple CPU cores for token generation
- **Scalability**: Handle high-throughput API scenarios

### Architecture Overview

```
Main Thread (Flutter)          Worker Thread (Pure Dart)
─────────────────────         ─────────────────────────
import 'solid_oidc_auth.dart'      import 'solid_oidc_auth/worker.dart'
                  
SolidOidcAuth                      DpopCredentials
├─ authenticate() ────────────> (serialize)
├─ exportDpopCredentials()     ├─ fromJson()
└─ (Flutter/OIDC flow)         └─ generateDpopToken()
```

### Basic Usage

```dart
// worker.dart - Pure Dart worker thread (NO Flutter imports!)
import 'dart:isolate';
import 'package:solid_oidc_auth/worker.dart'; // ← Flutter-free entry point

void workerEntryPoint(Map<String, dynamic> message) {
  final credentials = DpopCredentials.fromJson(message['credentials']);
  
  final dpop = credentials.generateDpopToken(
    url: message['url'] as String,
    method: message['method'] as String,
  );
  
  // Send result back to main thread
  final sendPort = message['sendPort'] as SendPort;
  sendPort.send({
    'dpopToken': dpop.dpopToken,
    'accessToken': dpop.accessToken,
  });
}
```

```dart
// main.dart - Main thread with Flutter
import 'package:solid_oidc_auth/solid_oidc_auth.dart';

Future<DPoP> generateInWorker(String url, String method) async {
  // Export credentials from authenticated session
  final credentials = solidAuth.exportDpopCredentials();
  
  // Spawn worker
  final receivePort = ReceivePort();
  await Isolate.spawn(workerEntryPoint, {
    'credentials': credentials.toJson(),
    'url': url,
    'method': method,
    'sendPort': receivePort.sendPort,
  });
  
  // Wait for result
  final response = await receivePort.first as Map<String, dynamic>;
  receivePort.close();
  
  return DPoP(
    dpopToken: response['dpopToken'] as String,
    accessToken: response['accessToken'] as String,
  );
}
```

### Parallel Token Generation

Generate multiple DPoP tokens in parallel for better performance:

```dart
import 'package:flutter/foundation.dart'; // for compute()

// Define top-level function for compute()
Map<String, String> _generateDpop(Map<String, dynamic> params) {
  final credentials = DpopCredentials.fromJson(params['credentials']);
  final dpop = credentials.generateDpopToken(
    url: params['url'] as String,
    method: params['method'] as String,
  );
  return {
    'dpopToken': dpop.dpopToken,
    'accessToken': dpop.accessToken,
  };
}

// Generate tokens in parallel
Future<List<DPoP>> generateMultipleTokens(
  List<String> urls,
  String method,
) async {
  final credentials = solidAuth.exportDpopCredentials();
  
  return Future.wait(
    urls.map((url) async {
      final result = await compute(_generateDpop, {
        'credentials': credentials.toJson(),
        'url': url,
        'method': method,
      });
      return DPoP(
        dpopToken: result['dpopToken']!,
        accessToken: result['accessToken']!,
      );
    }),
  );
}
```

### Important: Flutter-Free Entry Point

The `package:solid_oidc_auth/worker.dart` library is specifically designed to work without Flutter:

```dart
// ✅ Correct - Use in worker threads
import 'package:solid_oidc_auth/worker.dart';

// ❌ Wrong - Has Flutter dependencies
import 'package:solid_oidc_auth/solid_oidc_auth.dart';
```

**What's in `worker.dart`:**
- `DpopCredentials` - Serializable credentials
- `DPoP` - Token result container  
- `KeyPair` - Platform-agnostic RSA keys

**What's NOT in `worker.dart`:**
- `SolidOidcAuth` - Main authentication class (requires Flutter)
- OIDC flow management
- UI components
- Platform-specific storage

### Security Considerations for Workers

✅ **Safe:**
- Passing credentials to isolates in the same process
- Using `DpopCredentials.toJson()` for serialization
- Generating fresh tokens for each request

❌ **Unsafe:**
- Persisting serialized credentials to disk
- Sending credentials over the network
- Logging credentials in plaintext
- Sharing credentials between processes

### Complete Example

See [example/lib/dpop_worker_example.dart](example/lib/dpop_worker_example.dart) for a complete working example demonstrating:
- Worker thread setup with proper message passing
- Error handling in workers
- Parallel token generation
- Integration with the main authentication flow

### Further Documentation

For comprehensive information about worker thread patterns, security model, and best practices, see [doc/dpop_worker_threads.md](doc/dpop_worker_threads.md).

## 🔐 Client Configuration Guide

### Required Scopes

Your `client-profile.jsonld` **must** include these mandatory scopes:
- `openid`: Required for OpenID Connect authentication  
- `webid`: Required for Solid WebID functionality
- `offline_access`: Required for token refresh capability

### Redirect URI Patterns

The library automatically constructs redirect URIs based on your platform:

**Web Platform:**
- `redirect_uris`: Your exact `frontendRedirectUrl`
- `post_logout_redirect_uris`: Your exact `frontendRedirectUrl`

**Mobile/Desktop Platforms:**  
- `redirect_uris`: `{appUrlScheme}://redirect`
- `post_logout_redirect_uris`: `{appUrlScheme}://logout`

## 🔧 Platform Setup

**📚 Important**: For complete platform-specific setup instructions (web, iOS, Android, macOS, Windows, Linux), see the comprehensive [OIDC Getting Started Guide](https://bdaya-dev.github.io/oidc/oidc-getting-started/).

### Web Applications

Create a redirect handler HTML page at your `frontendRedirectUrl` location. **Use the official redirect.html from the [OIDC Getting Started Guide](https://bdaya-dev.github.io/oidc/oidc-getting-started/)** to ensure compatibility with the latest OIDC package version.

### Mobile & Desktop Applications

Each platform requires specific configuration for URL schemes and redirect handling. **Additionally, you must configure network permissions for Solid pod authentication to work properly.**

See the [OIDC Getting Started Guide](https://bdaya-dev.github.io/oidc/oidc-getting-started/) for detailed, up-to-date instructions for each platform.

#### 🌐 Required Network Permissions

Since Solid authentication requires network access to communicate with identity providers and pod servers, you must configure the following platform-specific network permissions:

**Android** - Add to `android/app/src/main/AndroidManifest.xml`:
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />
    <!-- Your existing application configuration -->
</manifest>
```

**macOS** - Add to both `macos/Runner/DebugProfile.entitlements` and `macos/Runner/Release.entitlements`:
```xml
<key>com.apple.security.network.client</key>
<true />
```

Example for `DebugProfile.entitlements`:
```xml
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true />
    <key>com.apple.security.network.server</key>
    <true />
    <key>com.apple.security.network.client</key>
    <true />
    <!-- Your existing entitlements -->
</dict>
```

⚠️ **Note**: Without these network permissions, authentication will fail silently or with network-related errors. These permissions are essential for connecting to Solid identity providers.

## 🔒 Security Considerations

- **HTTPS Required**: All redirect URIs must use HTTPS in production
- **Client Registration**: All redirect URIs must be listed in your client profile document  
- **DPoP Tokens**: Generate fresh DPoP tokens for each API request - never reuse them
- **Token Storage**: The library uses secure platform storage for sensitive data
- **WebID Validation**: WebIDs are validated by fetching profile documents and verifying identity providers

## 🌟 What is Solid?

[Solid](https://solidproject.org/) is a web decentralization project that gives users control over their data by storing it in personal data pods. Users authenticate with identity providers and grant applications specific access to their data.

## 📖 Additional Information

The source code can be accessed via [GitHub repository](https://github.com/locorda/solid_oidc_auth). You can also file issues you face at [GitHub Issues](https://github.com/locorda/solid_oidc_auth/issues).

An example project that demonstrates `solid_oidc_auth` usage can be found [here](https://github.com/locorda/solid_oidc_auth/tree/main/example).

## 🙏 Acknowledgments

This library builds upon the excellent work of the [Bdaya-Dev/oidc](https://github.com/Bdaya-Dev/oidc) team. We are standing on the shoulders of giants! 

Special thanks to:
- **[anusii/solid_auth](https://github.com/anusii/solid_auth)** - The original Solid authentication library from which this package was derived
- **[Bdaya-Dev/oidc](https://pub.dev/packages/oidc)** - The robust, well-maintained OpenID Connect implementation that powers this library
- **[oidc_default_store](https://pub.dev/packages/oidc_default_store)** - Secure, platform-appropriate token storage
- The broader Solid and OpenID Connect communities for their specifications and guidance

The solid_oidc_auth library focuses specifically on Solid pod authentication while leveraging these excellent foundational libraries for the core OIDC functionality.

## 🔗 Links

- [Solid Project](https://solidproject.org/)
- [Solid OIDC Specification](https://solid.github.io/solid-oidc/)  
- [WebID Specification](https://www.w3.org/2005/Incubator/webid/spec/identity/)
- [Example Application](https://github.com/locorda/solid_oidc_auth/tree/main/example)
- [Issue Tracker](https://github.com/locorda/solid_oidc_auth/issues)

---

## Roadmap

### Offline-First Support
Currently, `solid_oidc_auth` requires network connectivity during initialization to:
- Discover identity providers from WebID profiles
- Fetch OIDC provider configurations
- Validate authentication sessions

**Future Goal**: Enable fully offline-first applications that can start and function without network connectivity, using cached authentication data and provider configurations.

This is essential for truly offline-capable Solid applications, but requires careful consideration of security trade-offs and cache management strategies.

### Windows/Linux Desktop Support
The OIDC library supports Windows and Linux via localhost loopback device with random ports. 
Configuring `localhost:*` in the client profile probably is not a good idea for security reasons and possibly
disallowed by many Solid pod implementations, so we need to find out if this really is a problem or if it 
does work after all, or if we find some way to make it work for those two platforms.