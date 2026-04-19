/// Internal DPoP token generation utilities.
///
/// This module provides the core cryptographic logic for generating
/// DPoP (Demonstration of Proof-of-Possession) tokens as specified in
/// [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).
///
/// ## Architecture Note
///
/// This file is intentionally free of Flutter dependencies to enable:
/// - Use in worker threads/isolates via `package:solid_oidc_auth/worker.dart`
/// - Pure Dart testing without Flutter test harness
/// - Potential reuse in non-Flutter Dart projects
///
/// ## Internal API
///
/// This is not part of the public API. End users should use:
/// - `SolidOidcAuth.genDpopToken()` in the main thread
/// - `DpopCredentials.generateDpopToken()` in worker threads
library;

import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:solid_oidc_auth/src/rsa/rsa_api.dart';
import 'package:uuid/uuid.dart';

/// Generates a DPoP token for authenticated API requests.
///
/// Creates a signed JWT that proves possession of the private key corresponding
/// to the public key presented during OIDC authentication.
///
/// ## Parameters
///
/// - [endPointUrl]: The complete URL being accessed (e.g., 'https://alice.pod.com/data/')
/// - [rsaKeyPair]: Platform-agnostic RSA key pair with PEM-encoded keys
/// - [publicKeyJwk]: Public key in JWK format for the JWT header
/// - [httpMethod]: HTTP method being used (e.g., 'GET', 'POST', 'PUT', 'DELETE')
/// - [accessToken]: When present, the `ath` (access token hash) claim is added
///   to the proof as required by RFC 9449 §4.2 for resource-access DPoP proofs.
///
/// ## Return Value
///
/// Returns a signed JWT string in the format specified by RFC 9449:
/// - Header: `{"alg":"RS256","typ":"dpop+jwt","jwk":{...}}`
/// - Payload: `{"htu":"<url>","htm":"<method>","jti":"<uuid>","iat":<timestamp>}`
///   (plus `"ath":"<hash>"` when [accessToken] is supplied)
/// - Signature: RS256 signature using the private key
///
/// ## Specification References
///
/// - [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://datatracker.ietf.org/doc/html/rfc9449)
/// - [RFC 4122: UUID Generation](https://datatracker.ietf.org/doc/html/rfc4122) (for jti claim)
/// - [RFC 7519: JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) (JWT structure)
/// - [Solid-OIDC Primer](https://solid.github.io/solid-oidc/primer/#authorization-code-pkce-flow)
String genDpopToken(
  String endPointUrl,
  KeyPair rsaKeyPair,
  Map<String, dynamic> publicKeyJwk,
  String httpMethod, {
  String? accessToken,
}) {
  /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-03
  /// Unique identifier for DPoP proof JWT
  /// Here we are using a version 4 UUID according to https://datatracker.ietf.org/doc/html/rfc4122
  var uuid = const Uuid();
  final String tokenId = uuid.v4();

  /// Initialising token head and body (payload)
  /// https://solid.github.io/solid-oidc/primer/#authorization-code-pkce-flow
  /// https://datatracker.ietf.org/doc/html/rfc7519
  var tokenHead = {"alg": "RS256", "typ": "dpop+jwt", "jwk": publicKeyJwk};

  var tokenBody = <String, dynamic>{
    "htu": endPointUrl,
    "htm": httpMethod,
    "jti": tokenId,
  };

  // RFC 9449 §4.2: ath MUST be present when the proof accompanies an access
  // token (resource-access requests, Section 7).
  if (accessToken != null) {
    final hash = sha256.convert(ascii.encode(accessToken));
    tokenBody['ath'] = base64Url.encode(hash.bytes).replaceAll('=', '');
  }

  /// Create a json web token
  final jwt = JWT(
    tokenBody,
    header: tokenHead,
  );

  /// Sign the JWT using private key
  var dpopToken = jwt.sign(RSAPrivateKey(rsaKeyPair.privateKey),
      algorithm: JWTAlgorithm.RS256);

  return dpopToken;
}
