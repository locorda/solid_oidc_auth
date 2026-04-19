/// Platform-agnostic RSA key pair representation.
///
/// This class provides a simple, serializable representation of an RSA key pair
/// using PEM-encoded strings. Unlike platform-specific implementations (e.g.,
/// `fast_rsa.KeyPair`), this class can be safely used across all platforms
/// including web workers and isolates.
///
/// ## Usage
///
/// ```dart
/// final keyPair = KeyPair(
///   '-----BEGIN PUBLIC KEY-----...',
///   '-----BEGIN PRIVATE KEY-----...',
/// );
/// ```
///
/// ## Security
///
/// The private key should be treated as sensitive data and handled securely:
/// - Never log or display private keys
/// - Store securely using platform-appropriate secure storage
/// - Transfer only within trusted boundaries (same application)
class KeyPair {
  /// RSA public key in PEM format (PKCS#8).
  final String publicKey;

  /// RSA private key in PEM format (PKCS#8).
  ///
  /// **Warning**: This contains sensitive cryptographic material.
  final String privateKey;

  /// Creates a key pair from PEM-encoded strings.
  const KeyPair(this.publicKey, this.privateKey);
}

/// Result of RSA key pair generation, including both PEM and JWK representations.
///
/// This class encapsulates the complete result of generating an RSA key pair,
/// providing both the key pair itself and the public key in JWK format for use
/// in DPoP token headers.
///
/// ## Usage
///
/// ```dart
/// final result = await rsa.generate(2048);
/// final pem = result.rsaKeyPair.publicKey;
/// final jwk = result.publicKeyJwk; // For DPoP token headers
/// ```
class GeneratedRsaKeyPair {
  /// The generated RSA key pair in PEM format.
  final KeyPair rsaKeyPair;

  /// The public key in JSON Web Key (JWK) format.
  ///
  /// This format is required for DPoP token headers according to
  /// [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).
  /// The JWK includes the `alg: "RS256"` parameter.
  final dynamic publicKeyJwk;

  /// Creates a generation result with both PEM and JWK representations.
  const GeneratedRsaKeyPair({
    required this.rsaKeyPair,
    required this.publicKeyJwk,
  });
}

/// Abstract interface for RSA cryptographic operations.
///
/// This interface abstracts RSA key generation to allow platform-specific
/// implementations. Currently uses `fast_rsa` on all platforms for optimal
/// performance.
///
/// ## Why This Abstraction?
///
/// This abstraction was introduced to solve a specific problem: `fast_rsa.KeyPair`
/// could not be used in serializable types like `DpopCredentials` because it
/// depends on Flutter platform channels which are unavailable in web workers.
///
/// By introducing our own platform-agnostic `KeyPair` class, we can:
/// - Use `fast_rsa` for key generation (excellent performance)
/// - Pass the resulting keys safely across isolate/worker boundaries
/// - Serialize credentials without platform-specific dependencies
///
/// ## Implementation Strategy
///
/// All platforms currently use `fast_rsa` for key generation, because key
/// generation typically is done on the main thread where platform channels are
/// available. If you do need key generation in a web worker or isolate in the future,
/// a different implementation can be provided here and used via conditional imports.
///
/// ## Usage
///
/// ```dart
/// import 'package:solid_oidc_auth/src/rsa/rsa_impl.dart';
///
/// // Use the singleton instance
/// final result = await rsa.generate(2048);
/// final keyPair = result.rsaKeyPair;
/// final jwk = result.publicKeyJwk;
/// ```
///
/// ## Custom Implementation
///
/// To provide a custom implementation:
///
/// ```dart
/// class CustomRsaCrypto implements RsaCrypto {
///   @override
///   Future<GeneratedRsaKeyPair> generate([int bits = 2048]) async {
///     // Custom key generation logic
///     return GeneratedRsaKeyPair(
///       rsaKeyPair: KeyPair(publicPem, privatePem),
///       publicKeyJwk: jwkMap,
///     );
///   }
/// }
/// ```
abstract class RsaCrypto {
  /// Generates an RSA key pair with the specified bit length.
  ///
  /// ## Parameters
  ///
  /// - [bits]: The key size in bits. Common values:
  ///   - 2048: Standard security, good performance (default)
  ///   - 4096: Higher security, slower performance
  ///
  /// ## Return Value
  ///
  /// Returns a [GeneratedRsaKeyPair] containing:
  /// - The key pair in PEM format (PKCS#8)
  /// - The public key in JWK format with `alg: "RS256"`
  ///
  /// ## Example
  ///
  /// ```dart
  /// final result = await rsa.generate(2048);
  /// print('Public key: ${result.rsaKeyPair.publicKey}');
  /// print('JWK algorithm: ${result.publicKeyJwk['alg']}');
  /// ```
  Future<GeneratedRsaKeyPair> generate([int bits = 2048]);
}
