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
library solid_oidc_auth.src.gen_dpop_token;

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
///
/// ## Return Value
///
/// Returns a signed JWT string in the format specified by RFC 9449:
/// - Header: `{"alg":"RS256","typ":"dpop+jwt","jwk":{...}}`
/// - Payload: `{"htu":"<url>","htm":"<method>","jti":"<uuid>","iat":<timestamp>}`
/// - Signature: RS256 signature using the private key
///
/// ## Specification References
///
/// - [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://datatracker.ietf.org/doc/html/rfc9449)
/// - [RFC 4122: UUID Generation](https://datatracker.ietf.org/doc/html/rfc4122) (for jti claim)
/// - [RFC 7519: JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) (JWT structure)
/// - [Solid-OIDC Primer](https://solid.github.io/solid-oidc/primer/#authorization-code-pkce-flow)
String genDpopToken(String endPointUrl, KeyPair rsaKeyPair,
    dynamic publicKeyJwk, String httpMethod) {
  /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-03
  /// Unique identifier for DPoP proof JWT
  /// Here we are using a version 4 UUID according to https://datatracker.ietf.org/doc/html/rfc4122
  var uuid = const Uuid();
  final String tokenId = uuid.v4();

  /// Initialising token head and body (payload)
  /// https://solid.github.io/solid-oidc/primer/#authorization-code-pkce-flow
  /// https://datatracker.ietf.org/doc/html/rfc7519
  var tokenHead = {"alg": "RS256", "typ": "dpop+jwt", "jwk": publicKeyJwk};

  var tokenBody = {
    "htu": endPointUrl,
    "htm": httpMethod,
    "jti": tokenId,
  };

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
