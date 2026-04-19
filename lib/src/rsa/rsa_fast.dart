import 'rsa_api.dart';
import 'package:fast_rsa/fast_rsa.dart' as fast;

/// Native platform implementation of RSA crypto operations using fast_rsa.
///
/// This implementation provides high-performance RSA key generation by leveraging
/// the `fast_rsa` package.
///
/// ## Platform Support
///
/// This implementation is used on:
/// - iOS
/// - Android
/// - macOS
/// - Linux
/// - Windows
/// - Web
///
/// ## Performance
///
/// `fast_rsa` provides significantly better performance than pure Dart
/// implementations due to its use of native cryptographic libraries.
/// Key generation for 2048-bit keys typically completes in under 100ms.
///
/// ## Key Generation vs. Key Usage
///
/// While `fast_rsa` itself relies on Flutter platform channels (native) or
/// WebAssembly (web), the _resulting_ keys are just PEM strings. By converting
/// `fast_rsa.KeyPair` to our platform-agnostic `KeyPair` class, we enable:
///
/// - Key generation anywhere `fast_rsa` is available
/// - Key usage (signing) in workers/isolates using our existing JWT infrastructure
/// - Credential serialization without platform-specific dependencies
///
/// ## Implementation Details
///
/// The implementation performs the following steps:
/// 1. Generates an RSA key pair using `fast_rsa`
/// 2. Converts the fast_rsa-specific KeyPair to our platform-agnostic KeyPair
/// 3. Converts the public key to JWK format
/// 4. Adds the required `alg: "RS256"` parameter to the JWK
///
/// This ensures compatibility with DPoP token requirements while maintaining
/// the ability to pass keys across platform boundaries.
class RsaCryptoImpl implements RsaCrypto {
  /// Creates a new instance of the fast_rsa implementation.
  const RsaCryptoImpl();

  @override
  Future<GeneratedRsaKeyPair> generate([int bits = 2048]) async {
    // Generate key pair using fast_rsa's native implementation
    final keyPair = await fast.RSA.generate(bits);

    // Convert public key to JWK format for DPoP token headers
    final publicKeyJwk = Map<String, dynamic>.from(
        await fast.RSA.convertPublicKeyToJWK(keyPair.publicKey) as Map);

    // Return our platform-agnostic types with required algorithm parameter
    return GeneratedRsaKeyPair(
      rsaKeyPair: KeyPair(keyPair.publicKey, keyPair.privateKey),
      publicKeyJwk: {...publicKeyJwk, 'alg': 'RS256'},
    );
  }
}
