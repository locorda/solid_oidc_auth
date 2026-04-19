# DPoP Token Generation in Worker Threads

This document describes the worker thread support for DPoP token generation in SolidOidcAuth.

## Overview

SolidOidcAuth supports generating DPoP tokens in Dart isolates or web workers through the `DpopCredentials` API. This enables:

- Parallel DPoP token generation
- Offloading token generation from the main thread
- Better performance in high-throughput scenarios

## API

### Exporting Credentials

```dart
final solidAuth = SolidOidcAuth(/* ... */);
await solidAuth.authenticate('https://alice.pod.com/profile/card#me');

// Export credentials for worker thread
final credentials = solidAuth.exportDpopCredentials();
```

### Generating DPoP Tokens in Workers

```dart
// In worker thread/isolate
final credentials = DpopCredentials.fromJson(credentialsJson);
final dpop = credentials.generateDpopToken(
  url: 'https://alice.pod.com/data/file.txt',
  method: 'GET',
);

// Use dpop.httpHeaders() for HTTP requests
```

## Security Model

### What Gets Transferred

`DpopCredentials` contains:
- RSA private key (PEM format)
- RSA public key (PEM and JWK format)
- OAuth2 access token

### Security Boundary

The private key is transferred between threads **within your application process**. This is secure because:

1. **Process Isolation**: The OS protects your app's memory from other processes
2. **Same Security Context**: Workers run with the same permissions as the main thread
3. **Standard Practice**: Equivalent to multi-threaded crypto libraries (OpenSSL, BoringSSL)

### Safe Usage

✅ **SAFE - Intra-Process:**
```dart
// Dart isolate
await Isolate.spawn(worker, credentials.toJson());

// Flutter compute() - requires Map serialization
final result = await compute(workerFunc, {
  'credentials': credentials.toJson(),
  'url': url,
  'method': 'GET',
});

// Web worker (same-origin)
webWorker.postMessage(credentials.toJson());
```

❌ **UNSAFE - External:**
```dart
// Network transfer
http.post(url, body: credentials.toJson()); // NEVER

// Persistent storage
prefs.setString('creds', json); // NEVER

// Logging
print(credentials.privateKey); // NEVER
```

## Example: Using with Dart Isolates

See `example/dpop_worker_example.dart` for a complete implementation.

```dart
// Main thread
final credentials = solidAuth.exportDpopCredentials();
await Isolate.spawn(_workerFunction, {
  'sendPort': receivePort.sendPort,
  'credentials': credentials.toJson(),
  'url': url,
});

// Worker function
void _workerFunction(Map<String, dynamic> message) {
  final credentials = DpopCredentials.fromJson(message['credentials']);
  final dpop = credentials.generateDpopToken(
    url: message['url'],
    method: 'GET',
  );
  // Use dpop for HTTP requests...
}
```

## Example: Using with compute()

For simpler cases:

```dart
import 'package:flutter/foundation.dart';

// Top-level or static function for compute()
Map<String, String> _generateDpopInCompute(Map<String, dynamic> params) {
  final credentials = DpopCredentials.fromJson(params['credentials']);
  final dpop = credentials.generateDpopToken(
    url: params['url'] as String,
    method: params['method'] as String,
  );
  // Return serializable Map
  return {
    'dpopToken': dpop.dpopToken,
    'accessToken': dpop.accessToken,
  };
}

// Usage
final credentials = solidAuth.exportDpopCredentials();
final result = await compute(
  _generateDpopInCompute,
  {
    'credentials': credentials.toJson(),
    'url': 'https://alice.pod.com/data/',
    'method': 'GET',
  },
);

// Reconstruct DPoP object on main thread
final dpop = DPoP(
  dpopToken: result['dpopToken']!,
  accessToken: result['accessToken']!,
);
```

## When to Use

**Use worker threads when:**
- Generating many DPoP tokens concurrently
- Main thread responsiveness is critical
- Profiling shows DPoP generation is a bottleneck

**Use main thread (simpler) when:**
- Generating a few tokens occasionally
- Simplicity is more important than performance

```dart
// Main thread (simpler, sufficient for most apps)
final dpop = solidAuth.genDpopToken(url, method);
```

## Performance Considerations

Worker threads add overhead (~10-50ms per isolate spawn). Benefits are only visible when:
- Generating multiple tokens in parallel
- Token generation would otherwise block the main thread

Profile your specific use case to determine if workers provide benefits.
