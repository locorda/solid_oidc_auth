import 'package:flutter_test/flutter_test.dart';
import 'package:oidc/oidc.dart';
import 'package:solid_oidc_auth/solid_oidc_auth.dart';

void main() {
  group('SolidOidcAuth', () {
    late SolidOidcAuth solidAuth;

    setUp(() {
      solidAuth = SolidOidcAuth(
        oidcClientId: 'https://example.com/client-profile.jsonld',
        appUrlScheme: 'com.example.test',
        frontendRedirectUrl: Uri.parse('https://example.com/redirect.html'),
        store: OidcMemoryStore(),
      );
    });

    group('before authenticate()', () {
      test('genDpopToken throws StateError', () {
        expect(
          () => solidAuth.genDpopToken('https://alice.pod.com/data', 'GET'),
          throwsA(isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('authenticate()'),
          )),
        );
      });

      test('exportDpopCredentials throws StateError', () {
        expect(
          () => solidAuth.exportDpopCredentials(),
          throwsA(isA<StateError>()),
        );
      });

      test('isAuthenticated returns false', () {
        expect(solidAuth.isAuthenticated, isFalse);
      });

      test('currentWebId returns null', () {
        expect(solidAuth.currentWebId, isNull);
      });

      test('isAuthenticatedNotifier has false value', () {
        expect(solidAuth.isAuthenticatedNotifier.value, isFalse);
      });
    });

    group('init()', () {
      test('returns false when no stored session exists', () async {
        final result = await solidAuth.init();
        expect(result, isFalse);
      });

      test('can be called multiple times safely', () async {
        await solidAuth.init();
        // Second call must not throw even though _manager was null.
        await expectLater(solidAuth.init(), completes);
      });
    });

    group('logout()', () {
      test('is idempotent when not authenticated', () async {
        await expectLater(solidAuth.logout(), completes);
        expect(solidAuth.isAuthenticated, isFalse);
      });
    });

    group('dispose()', () {
      test('can be called before authentication', () async {
        await expectLater(solidAuth.dispose(), completes);
      });
    });
  });
}
