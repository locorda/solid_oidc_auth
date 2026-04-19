import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:solid_oidc_auth/src/gen_dpop_token.dart';
import 'package:solid_oidc_auth/src/rsa/rsa_api.dart';

// Pre-generated RSA 2048-bit key pair for testing purposes only.
// NEVER use these keys for anything other than tests.
const _testPublicKey = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0qK40YyYmL5qlfCBD79+
J3qZKpwDChjaXdKrPjAPGsD5m6Q+sk3YULZ+1xHLSbpf3kRNptfHHcvRjSsezSot
8y2Q7/V2YdnTBl7IWKQtCf6LpdSnDtp2M02b/odMaXA4L8TD8O+QCb3h7ondAO01
Vm7ENxee4pl+DD9CCMc8gxMgFEIposVlXB+wJKXe6oQ29+KG12YVR7FE0cOrpkrA
wwNoebVqVkZMbXFqZYRPOM1NNkobMx2ThqxONRr+Xe2dhkpqByBaexr5yrcEvex/
F++a+RVci0vL+rG77H/vfOdyAHx7sYuJj4yCz0qwHbh1XWWJQp4v6WY01RnOumEF
VQIDAQAB
-----END PUBLIC KEY-----''';

const _testPrivateKey = '''-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSorjRjJiYvmqV
8IEPv34nepkqnAMKGNpd0qs+MA8awPmbpD6yTdhQtn7XEctJul/eRE2m18cdy9GN
Kx7NKi3zLZDv9XZh2dMGXshYpC0J/oul1KcO2nYzTZv+h0xpcDgvxMPw75AJveHu
id0A7TVWbsQ3F57imX4MP0IIxzyDEyAUQimixWVcH7Akpd7qhDb34obXZhVHsUTR
w6umSsDDA2h5tWpWRkxtcWplhE84zU02ShszHZOGrE41Gv5d7Z2GSmoHIFp7GvnK
twS97H8X75r5FVyLS8v6sbvsf+9853IAfHuxi4mPjILPSrAduHVdZYlCni/pZjTV
Gc66YQVVAgMBAAECggEAOTUfvC4S3d1NpoaJDwVj1oYaJnPz8WCZokTO5Jd56rrB
sE92BchVuWovXetDyrT3R69GZcuSFVofgldVSMStcTANftasfdwCz+abRFPmtaGw
POxaKRMVak6oUQNfMf3cDMFEtGHkPXkYbUh9QTyrsVtpKEteiE3G6b2eijLOkQx4
oluuqB7VF+6U3PEu8L13Vwkm2JrMXfjcKqgnA/VtU2EsrFIMDx1NnY+IQ0OilxmL
C6DO2UaqgiKFmHfqtjxLub8I66gEKA9DKuVhu3aQJSK2UcZYt1lNYuuxOrVc2k3N
kJGSkR8G3G/bFeumXpk7ND3y5OpG0EfMEkIjvwQQWwKBgQD8plLNTG6P5vO7UPQG
/J5ZibYo4aZWYWievdVtHYlo4VQeOw56r28vy5GqCKXIXZdselkzu+4YRhCLX5XV
TrkH9ILyJsL/9katVBsY0vRl7S3rmarbJI66jCCsBbLH4kZVIUmDfK3g82E6nVwk
CrPK1JsSteHRVmRyiMHDjfdDYwKBgQDVbcWx0Jq3Pl1texOjcuwc6+tCbaViFCON
8aNqzxQ18vNpYCVF6knlCfx9c5LIqOJqIIMjR+ctScFWyx1CV205Chz6AYCvzGIO
SSrF7cxYbN4RxTDeNyscofJdQG5siV5CCbRSugngrjG/IGVxSJADXE+e7iye+IJe
Z36yRCsd5wKBgQDxtIU+10Jm9UJ0D+yFyqQLcQ4OamJh/WrDg0Vt0HYnGnsJOOKP
SMsMZKqEiyVfXPqC00IHlmEgY9dsHxQPL/MgwzGLTL39drUDGZWa2CbsZE4sOaUV
ZhIOMgUHzaPOSpGS2/eijWMj9HMuSmFeMcbz4xZAfjT9urL6SA9ncKf/lQKBgDA/
K2Sh8oef+oDIRM07KnLzRfBzVuKQCOWKjVWU0E3NyQa2LFbcuq2jD0fQu4rO2rgA
94QfOfw74w/axJd9qfwt9BT0CAI1oqj2E0xBEGOg4KaFvCFPuVg0p9Q6v3ubpgop
pXDaC2eWGTrKeQQd0ihgUsNrtfyN0vLCVJq53EFbAoGAGqiWSe4yZLcj4mU2JS7w
ZIfRnE4uMgoQDqeISZ+5Tt//S23SAUReWgxsYvK8jbvqWzZiKJsiIZQP8vKpeLhp
E0I+Jr9oFA/Cmxov0EjhcnT01+4939wChKO1taJAuky4wdEfOLIq+hWrp9WZKvTT
Txb6UaM6nInxC8z1EE8Rklg=
-----END PRIVATE KEY-----''';

// Minimal JWK for the test — structure mirrors what rsa_fast produces.
const _testPublicKeyJwk = <String, dynamic>{
  'kty': 'RSA',
  'alg': 'RS256',
  'n': 'test_modulus',
  'e': 'AQAB',
};

void main() {
  group('genDpopToken — RFC 9449 compliance', () {
    const url = 'https://example.solidcommunity.net/profile/card';
    const method = 'GET';
    final keyPair = KeyPair(_testPublicKey, _testPrivateKey);

    // Shared token generated once per group to avoid repeated signing overhead.
    late String token;
    late Map<String, dynamic> payload;
    late Map<String, dynamic> header;

    setUpAll(() {
      token = genDpopToken(url, keyPair, _testPublicKeyJwk, method);
      final jwt = JWT.decode(token);
      payload = jwt.payload as Map<String, dynamic>;
      header = jwt.header ?? {};
    });

    // RFC 9449 §4.2: The iat claim MUST be present.
    // We rely on dart_jsonwebtoken automatically injecting iat during sign().
    // This test guards against upstream behaviour changes (e.g. noIssueAt flag
    // inadvertently introduced) that would silently break RFC compliance.
    test('iat claim is present (auto-injected by dart_jsonwebtoken)', () {
      expect(
        payload.containsKey('iat'),
        isTrue,
        reason: 'RFC 9449 §4.2 requires iat; dart_jsonwebtoken injects it automatically during JWT.sign()',
      );
    });

    test('iat reflects current time within a 5-second window', () {
      final nowSeconds = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final iat = (payload['iat'] as num).toInt();
      expect(iat, greaterThanOrEqualTo(nowSeconds - 5));
      expect(iat, lessThanOrEqualTo(nowSeconds + 1));
    });

    // RFC 9449 §4.2: htu and htm MUST be present.
    test('htu claim equals the requested URL', () {
      expect(payload['htu'], equals(url));
    });

    test('htm claim equals the HTTP method', () {
      expect(payload['htm'], equals(method));
    });

    // RFC 9449 §4.2: jti MUST be a unique, non-empty string.
    test('jti claim is a non-empty string', () {
      expect(payload['jti'], isA<String>());
      expect((payload['jti'] as String), isNotEmpty);
    });

    test('jti is unique across two tokens for the same URL', () {
      final token2 = genDpopToken(url, keyPair, _testPublicKeyJwk, method);
      final jti1 = payload['jti'] as String;
      final jti2 = (JWT.decode(token2).payload as Map<String, dynamic>)['jti'] as String;
      expect(jti1, isNot(equals(jti2)));
    });

    // RFC 9449 §4.2: typ header MUST be dpop+jwt.
    test('typ header is dpop+jwt', () {
      expect(header['typ'], equals('dpop+jwt'));
    });

    // RFC 9449 §4.2: alg header MUST be an asymmetric algorithm (RS256 here).
    test('alg header is RS256', () {
      expect(header['alg'], equals('RS256'));
    });

    // RFC 9449 §4.2: jwk header MUST contain the public key.
    test('jwk header is present', () {
      expect(header.containsKey('jwk'), isTrue);
      expect(header['jwk'], isA<Map>());
    });

    test('htm reflects different HTTP methods', () {
      for (final httpMethod in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) {
        final t = genDpopToken(url, keyPair, _testPublicKeyJwk, httpMethod);
        final p = JWT.decode(t).payload as Map<String, dynamic>;
        expect(p['htm'], equals(httpMethod));
      }
    });
  });
}
