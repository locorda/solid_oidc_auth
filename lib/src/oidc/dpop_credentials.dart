import 'package:solid_oidc_auth/src/rsa/rsa_api.dart' show KeyPair;
import 'package:solid_oidc_auth/src/gen_dpop_token.dart' as solid_auth_client;

/// Serializable credentials for generating DPoP tokens in worker threads/isolates.
///
/// This class contains all the necessary data to generate DPoP tokens without
/// requiring access to the full [SolidOidcAuth] instance. It's designed to be
/// safely transferred to Dart isolates or web workers.
///
/// ## ⚠️ Contains Sensitive Cryptographic Material
///
/// This class holds your **RSA private key** and **OAuth2 access token**.
/// These credentials enable secure intra-process transfer to worker threads
/// while maintaining the security boundary of your application.
///
/// ## Quick Example
///
/// ```dart
/// // Main thread
/// final credentials = solidAuth.exportDpopCredentials();
/// await Isolate.spawn(workerFunction, credentials.toJson());
///
/// // Worker thread
/// void workerFunction(Map<String, dynamic> json) {
///   final credentials = DpopCredentials.fromJson(json);
///   final dpop = credentials.generateDpopToken(
///     url: 'https://alice.pod.com/data/',
///     method: 'GET',
///   );
/// }
/// ```
///
/// ## Complete Documentation
///
/// For detailed security guidelines, usage patterns, and best practices, see:
/// **[doc/dpop_worker_threads.md](../../doc/dpop_worker_threads.md)**
///
/// The documentation covers:
/// - Security model and trust boundaries
/// - Safe vs. unsafe usage patterns
/// - Complete examples for isolates, compute(), and web workers
/// - Thread safety considerations
class DpopCredentials {
  /// RSA public key in PEM format
  final String publicKey;

  /// RSA private key in PEM format
  ///
  /// **Warning**: This is sensitive cryptographic material. Handle with care.
  final String privateKey;

  /// Public key in JSON Web Key (JWK) format
  final Map<String, dynamic> publicKeyJwk;

  /// OAuth2 access token for the authenticated user
  ///
  /// **Warning**: This is a bearer token that grants access to resources.
  final String accessToken;

  DpopCredentials({
    required this.publicKey,
    required this.privateKey,
    required Map<String, dynamic> publicKeyJwk,
    required this.accessToken,
  }) : publicKeyJwk = Map<String, dynamic>.unmodifiable(publicKeyJwk);

  /// Serializes the credentials to JSON for transfer to workers.
  ///
  /// The resulting map can be:
  /// - Converted to JSON string via `jsonEncode(credentials.toJson())`
  /// - Sent directly via isolate SendPort
  /// - Posted to web workers via postMessage
  Map<String, dynamic> toJson() => {
        'publicKey': publicKey,
        'privateKey': privateKey,
        'publicKeyJwk': publicKeyJwk,
        'accessToken': accessToken,
      };

  /// Deserializes credentials from JSON received from the main thread.
  ///
  /// Example:
  /// ```dart
  /// // From JSON string
  /// final credentials = DpopCredentials.fromJson(jsonDecode(jsonString));
  ///
  /// // From map received via isolate
  /// final credentials = DpopCredentials.fromJson(messageFromMain);
  /// ```
  factory DpopCredentials.fromJson(Map<String, dynamic> json) =>
      DpopCredentials(
        publicKey: json['publicKey'] as String,
        privateKey: json['privateKey'] as String,
        publicKeyJwk: json['publicKeyJwk'] as Map<String, dynamic>,
        accessToken: json['accessToken'] as String,
      );

  /// Generates a DPoP token using these credentials.
  ///
  /// This method can be called from any thread (main thread, isolate, or web worker)
  /// without requiring access to a [SolidOidcAuth] instance. It's designed for use cases where
  /// DPoP token generation needs to happen on a worker thread for performance reasons.
  ///
  /// ## Parameters
  ///
  /// - [url]: The complete URL of the API endpoint being accessed
  /// - [method]: The HTTP method ('GET', 'POST', 'PUT', 'DELETE', etc.)
  ///
  /// ## Return Value
  ///
  /// Returns a [DPoP] object containing both the DPoP proof token and access token.
  ///
  /// ## Example
  ///
  /// ```dart
  /// // In a worker/isolate
  /// void workerFunction(Map<String, dynamic> credentialsJson) {
  ///   final credentials = DpopCredentials.fromJson(credentialsJson);
  ///   final dpop = credentials.generateDpopToken(
  ///     url: 'https://alice.pod.com/data/file.txt',
  ///     method: 'GET',
  ///   );
  ///
  ///   // Use in HTTP request
  ///   final response = await http.get(
  ///     Uri.parse('https://alice.pod.com/data/file.txt'),
  ///     headers: dpop.httpHeaders(),
  ///   );
  /// }
  /// ```
  ///
  /// ## Security
  ///
  /// - Each DPoP token is bound to the specific URL and HTTP method
  /// - Tokens include a unique nonce and timestamp
  /// - Tokens should be generated fresh for each request
  /// - The private key never leaves the credentials object
  DPoP generateDpopToken({
    required String url,
    required String method,
  }) {
    final rsaKeyPair = KeyPair(publicKey, privateKey);
    final dpopToken = solid_auth_client.genDpopToken(
      url,
      rsaKeyPair,
      publicKeyJwk,
      method,
      accessToken: accessToken,
    );

    return DPoP(dpopToken: dpopToken, accessToken: accessToken);
  }
}

/// Contains DPoP token and access token for authenticated API requests to Solid servers.
///
/// DPoP (Demonstration of Proof-of-Possession) is a security mechanism required
/// by Solid servers to prove that the client making an API request is the same
/// client to which the access token was issued. This prevents token theft and replay attacks.
///
/// ## Usage
///
/// Typically obtained from [SolidOidcAuth.genDpopToken] and used to make authenticated
/// requests to Solid pod resources.
///
/// ```dart
/// final dpop = solidAuth.genDpopToken('https://alice.pod.com/data/', 'GET');
///
/// // Use convenience method with additional headers
/// final response = await http.get(
///   Uri.parse('https://alice.pod.com/data/'),
///   headers: {
///     ...dpop.httpHeaders(),
///     'Accept': 'text/turtle',
///   },
/// );
///
/// // Or construct headers manually
/// final response = await http.get(
///   Uri.parse('https://alice.pod.com/data/'),
///   headers: {
///     'Authorization': 'DPoP ${dpop.accessToken}',
///     'DPoP': dpop.dpopToken,
///     'Accept': 'text/turtle',
///   },
/// );
/// ```
class DPoP {
  /// The DPoP JWT token that proves possession of the access token.
  ///
  /// This is a signed JWT that includes:
  /// - The HTTP method and URL being accessed
  /// - A unique nonce to prevent replay attacks
  /// - A timestamp showing when the token was created
  /// - The public key corresponding to the private key used for signing
  final String dpopToken;

  /// The OAuth2 access token for the authenticated user.
  ///
  /// This token grants access to resources but must be accompanied by the
  /// [dpopToken] to prove possession when making requests to Solid servers.
  final String accessToken;

  DPoP({required this.dpopToken, required this.accessToken});

  /// Returns HTTP headers formatted for Solid API requests.
  ///
  /// This is the recommended way to use DPoP tokens with HTTP clients.
  /// The returned map contains:
  /// - `Authorization`: 'DPoP {accessToken}'
  /// - `DPoP`: The DPoP JWT token
  ///
  /// ## Example
  /// ```dart
  /// final dpop = solidAuth.genDpopToken('https://alice.pod.com/data/', 'GET');
  /// final response = await http.get(
  ///   Uri.parse('https://alice.pod.com/data/'),
  ///   headers: {
  ///     ...dpop.httpHeaders(),
  ///     'Accept': 'text/turtle',
  ///   },
  /// );
  /// ```
  Map<String, String> httpHeaders() => {
        'Authorization': 'DPoP $accessToken',
        'DPoP': dpopToken,
      };
}
