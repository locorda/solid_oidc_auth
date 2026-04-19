import 'rsa_api.dart';
// You can use conditional imports if you have different implementations like below
// import 'rsa_fast.dart' if (dart.library.html) 'rsa_web.dart';
import 'rsa_fast.dart';

/// Singleton instance of the RSA crypto implementation.
///
/// This constant provides access to RSA key generation functionality using
/// `fast_rsa` for optimal performance on all platforms:
///
/// ## Usage
///
/// ```dart
/// import 'package:solid_oidc_auth/src/rsa/rsa_impl.dart';
///
/// // Generate a key pair
/// final result = await rsa.generate(2048);
///
/// // Access the PEM-encoded keys
/// final publicPem = result.rsaKeyPair.publicKey;
/// final privatePem = result.rsaKeyPair.privateKey;
///
/// // Access the JWK for DPoP headers
/// final jwk = result.publicKeyJwk;
/// ```
///
/// ## Why This Abstraction?
///
/// The abstraction layer solves a critical problem: `fast_rsa.KeyPair` could
/// not be used in serializable types (like `DpopCredentials`) because it
/// depends on platform-specific code that is unavailable in web workers and
/// isolates.
///
/// By introducing our own platform-agnostic `KeyPair` class, we can:
///
/// 1. Use `fast_rsa` for optimal key generation performance
/// 2. Pass key pairs safely across isolate/worker boundaries
/// 3. Serialize credentials without platform-specific type dependencies
///
/// The key insight: we never needed to _call_ `fast_rsa` in workers - we just
/// needed to _use_ the KeyPair type. By creating our own simple KeyPair class
/// and separating KeyPair type from key generation implementation,
/// the problem disappeared.
const RsaCrypto rsa = RsaCryptoImpl();
