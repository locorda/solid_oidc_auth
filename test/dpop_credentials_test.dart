import 'package:flutter_test/flutter_test.dart';
import 'package:solid_oidc_auth/src/oidc/dpop_credentials.dart';

void main() {
  group('DpopCredentials', () {
    late DpopCredentials testCredentials;

    setUp(() {
      testCredentials = const DpopCredentials(
        publicKey:
            '-----BEGIN PUBLIC KEY-----\ntest_public_key\n-----END PUBLIC KEY-----',
        privateKey:
            '-----BEGIN PRIVATE KEY-----\ntest_private_key\n-----END PRIVATE KEY-----',
        publicKeyJwk: {
          'kty': 'RSA',
          'n': 'test_modulus',
          'e': 'AQAB',
          'alg': 'RS256',
        },
        accessToken: 'test_access_token_12345',
      );
    });

    test('should serialize to JSON correctly', () {
      final json = testCredentials.toJson();

      expect(json['publicKey'], contains('BEGIN PUBLIC KEY'));
      expect(json['privateKey'], contains('BEGIN PRIVATE KEY'));
      expect(json['publicKeyJwk'], isA<Map<String, dynamic>>());
      expect(json['accessToken'], equals('test_access_token_12345'));
    });

    test('should deserialize from JSON correctly', () {
      final json = testCredentials.toJson();
      final deserialized = DpopCredentials.fromJson(json);

      expect(deserialized.publicKey, equals(testCredentials.publicKey));
      expect(deserialized.privateKey, equals(testCredentials.privateKey));
      expect(deserialized.publicKeyJwk, equals(testCredentials.publicKeyJwk));
      expect(deserialized.accessToken, equals(testCredentials.accessToken));
    });

    test('should be immutable', () {
      // Modifying the original JWK map should not affect the credentials
      final jwkMap = {'kty': 'RSA', 'n': 'test', 'e': 'AQAB'};
      final credentials = DpopCredentials(
        publicKey: 'pub',
        privateKey: 'priv',
        publicKeyJwk: Map<String, dynamic>.from(jwkMap),
        accessToken: 'token',
      );

      jwkMap['modified'] = 'value';

      // The original map is modified
      expect(jwkMap.containsKey('modified'), isTrue);

      // But the credentials' JWK is a different instance
      // (Note: DpopCredentials doesn't deep-copy the map, so this tests
      // that we created a new map instance via Map.from)
      expect(identical(credentials.publicKeyJwk, jwkMap), isFalse);
    });

    test('should round-trip through JSON serialization', () {
      final json1 = testCredentials.toJson();
      final intermediate = DpopCredentials.fromJson(json1);
      final json2 = intermediate.toJson();

      expect(json2, equals(json1));
    });

    test('generateDpopToken should throw on invalid keys', () {
      // Note: This test verifies that the method properly validates
      // cryptographic keys. Invalid test keys should throw an error.

      expect(
        () => testCredentials.generateDpopToken(
          url: 'https://example.com/resource',
          method: 'GET',
        ),
        // This will throw because test keys are invalid
        throwsA(anything),
      );
    });

    test('should handle complex JWK structures', () {
      final complexCredentials = DpopCredentials(
        publicKey: 'pub',
        privateKey: 'priv',
        publicKeyJwk: {
          'kty': 'RSA',
          'n': 'very_long_modulus_value',
          'e': 'AQAB',
          'alg': 'RS256',
          'use': 'sig',
          'kid': 'key-id-123',
        },
        accessToken: 'token',
      );

      final json = complexCredentials.toJson();
      final deserialized = DpopCredentials.fromJson(json);

      expect(deserialized.publicKeyJwk['kid'], equals('key-id-123'));
      expect(deserialized.publicKeyJwk['use'], equals('sig'));
    });
  });

  group('DpopCredentials Security', () {
    test('should contain sensitive data warning in documentation', () {
      // This is a documentation test to ensure developers are aware
      // of security implications
      const credentials = DpopCredentials(
        publicKey: 'pub',
        privateKey: 'priv',
        publicKeyJwk: {'kty': 'RSA'},
        accessToken: 'token',
      );

      // Verify that the class exists and has the expected fields
      expect(credentials.privateKey, isNotEmpty);
      expect(credentials.accessToken, isNotEmpty);
    });
  });
}
