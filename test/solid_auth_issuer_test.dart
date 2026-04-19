import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:locorda_rdf_core/core.dart';
import 'package:solid_oidc_auth/src/solid_auth_issuer.dart';

// Mirrors the private constant in solid_auth_issuer.dart for use in test fixtures.
const _solidOidcIssuerForTest = 'http://www.w3.org/ns/solid/terms#oidcIssuer';

void main() {
  group('getIssuerUris', () {
    const webId = 'https://alice.solidcommunity.net/profile/card#me';
    const issuer = 'https://solidcommunity.net';

    test('extracts solid:oidcIssuer from a valid Turtle profile', () {
      final turtle = '''
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
<$webId> solid:oidcIssuer <$issuer> .
''';
      expect(getIssuerUris(turtle, webId), equals([issuer]));
    });

    test('returns all issuers when multiple triples exist', () {
      final turtle = '''
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
<$webId> solid:oidcIssuer <https://first.example.com> , <https://second.example.com> .
''';
      final result = getIssuerUris(turtle, webId);
      expect(
          result,
          unorderedEquals(
              ['https://first.example.com', 'https://second.example.com']));
    });

    test('throws ArgumentError when no solid:oidcIssuer triple exists', () {
      const turtle = '''
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
<$webId> foaf:name "Alice" .
''';
      expect(
        () => getIssuerUris(turtle, webId),
        throwsA(isA<ArgumentError>().having(
          (e) => e.message,
          'message',
          contains('No solid:oidcIssuer IRI found'),
        )),
      );
    });

    // A literal value is invalid per spec; the filter discards it, leaving an
    // empty list which triggers the same ArgumentError as "no triple found".
    test('throws ArgumentError when solid:oidcIssuer value is a literal', () {
      final turtle = '''
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
<$webId> solid:oidcIssuer "https://solidcommunity.net" .
''';
      expect(
        () => getIssuerUris(turtle, webId),
        throwsA(isA<ArgumentError>().having(
          (e) => e.message,
          'message',
          contains('No solid:oidcIssuer IRI found'),
        )),
      );
    });
  });

  group('getIssuers (direct issuer URI, no HTTP)', () {
    test('returns a single-element list for a direct issuer URI', () async {
      final result = await getIssuers('https://solidcommunity.net');
      expect(result, equals([Uri.parse('https://solidcommunity.net')]));
    });

    test('treats URL without fragment as direct issuer, not WebID', () async {
      // A URL without a fragment must be treated as a direct issuer URI —
      // no HTTP fetch should occur.
      final result = await getIssuers('https://solidcommunity.net/auth');
      expect(result, equals([Uri.parse('https://solidcommunity.net/auth')]));
    });

    test('throws ArgumentError for a URI without scheme', () async {
      expect(
        () => getIssuers('solidcommunity.net'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('getIssuers (WebID, with mock HTTP)', () {
    const webId = 'https://alice.solidcommunity.net/profile/card#me';
    const issuer = 'https://solidcommunity.net';

    test('fetches profile and returns single-element issuer list', () async {
      final turtle = '''
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
<$webId> solid:oidcIssuer <$issuer> .
''';
      final client = MockClient((request) async {
        expect(request.url.toString(), equals(webId));
        expect(request.headers['Accept'],
            equals('text/turtle, application/n-triples;q=0.9'));
        return http.Response(turtle, 200,
            headers: {'content-type': 'text/turtle'});
      });

      final result = await getIssuers(webId, httpClient: client);
      expect(result, equals([Uri.parse(issuer)]));
    });

    test(
        'returns all issuers when profile has multiple solid:oidcIssuer triples',
        () async {
      const issuer2 = 'https://other.solidcommunity.net';
      final turtle = '''
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
<$webId> solid:oidcIssuer <$issuer> , <$issuer2> .
''';
      final client = MockClient((_) async => http.Response(
            turtle,
            200,
            headers: {'content-type': 'text/turtle'},
          ));

      final result = await getIssuers(webId, httpClient: client);
      expect(result, unorderedEquals([Uri.parse(issuer), Uri.parse(issuer2)]));
    });

    test('propagates HTTP error without silent fallback', () async {
      final client = MockClient((_) async => http.Response('Not Found', 404));

      expect(
        () => getIssuers(webId, httpClient: client),
        throwsA(isA<Exception>().having(
          (e) => e.toString(),
          'message',
          contains('HTTP 404'),
        )),
      );
    });

    test('throws ArgumentError when profile has no solid:oidcIssuer', () async {
      const turtle = '''
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
<$webId> foaf:name "Alice" .
''';
      final client = MockClient((_) async => http.Response(turtle, 200));

      expect(
        () => getIssuers(webId, httpClient: client),
        throwsA(isA<ArgumentError>()),
      );
    });

    test(
        'decodes N-Triples response when content-type is application/n-triples',
        () async {
      final nTriples = '<$webId> <$_solidOidcIssuerForTest> <$issuer> .\n';
      final client = MockClient((_) async => http.Response(
            nTriples,
            200,
            headers: {'content-type': 'application/n-triples'},
          ));

      final result = await getIssuers(webId, httpClient: client);
      expect(result, equals([Uri.parse(issuer)]));
    });

    test('getIssuerUris parses N-Triples when contentType is set', () {
      final nTriples = '<$webId> <$_solidOidcIssuerForTest> <$issuer> .\n';
      expect(
        getIssuerUris(nTriples, webId, contentType: 'application/n-triples'),
        equals([issuer]),
      );
    });

    test('detects WebID by fragment — non-standard URL pattern', () async {
      // WebIDs like https://id.example.com/alice#me must also trigger a
      // profile fetch, not be silently treated as a direct issuer URI.
      const nonStandardWebId = 'https://id.example.com/alice#me';
      final turtle = '''
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
<$nonStandardWebId> solid:oidcIssuer <https://auth.example.com> .
''';
      final client = MockClient((request) async {
        expect(request.url.toString(), equals(nonStandardWebId));
        return http.Response(turtle, 200,
            headers: {'content-type': 'text/turtle'});
      });

      final result = await getIssuers(nonStandardWebId, httpClient: client);
      expect(result, equals([Uri.parse('https://auth.example.com')]));
    });

    test('getIssuerUris accepts injected RdfCore with custom TurtleCodec', () {
      // Non-standard Turtle: prefix declaration missing the trailing dot.
      final nonStandardTurtle = '''
@prefix solid: <http://www.w3.org/ns/solid/terms#>
<$webId> solid:oidcIssuer <$issuer> .
''';
      final customRdf = RdfCore.withCodecs(codecs: [
        TurtleCodec(
          decoderOptions: TurtleDecoderOptions(
            parsingFlags: {TurtleParsingFlag.allowMissingDotAfterPrefix},
          ),
        ),
      ]);
      expect(
        getIssuerUris(nonStandardTurtle, webId, rdfCore: customRdf),
        equals([issuer]),
      );
    });
  });

  group('_assertSecureUrl (via getIssuers)', () {
    test('allows HTTPS WebID', () async {
      const turtle = '''
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
<https://alice.example.com/profile/card#me> solid:oidcIssuer <https://example.com> .
''';
      final client = MockClient((_) async => http.Response(turtle, 200));

      expect(
        () => getIssuers('https://alice.example.com/profile/card#me',
            httpClient: client),
        returnsNormally,
      );
    });

    test('allows HTTP localhost WebID', () async {
      const turtle = '''
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
<http://localhost:3000/profile/card#me> solid:oidcIssuer <http://localhost:3000> .
''';
      final client = MockClient((_) async => http.Response(turtle, 200));

      expect(
        () => getIssuers('http://localhost:3000/profile/card#me',
            httpClient: client),
        returnsNormally,
      );
    });

    test('allows HTTP IPv6 loopback WebID', () async {
      const turtle = '''
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
<http://[::1]:3000/profile/card#me> solid:oidcIssuer <http://[::1]:3000> .
''';
      final client = MockClient((_) async => http.Response(turtle, 200));
      final issuers = await getIssuers('http://[::1]:3000/profile/card#me',
          httpClient: client);
      expect(
        issuers.map((uri) => uri.toString()).toList(),
        equals(['http://[::1]:3000']),
      );
    });

    test('rejects HTTP non-localhost WebID', () async {
      expect(
        () => getIssuers('http://alice.example.com/profile/card#me'),
        throwsA(isA<ArgumentError>().having(
          (e) => e.message,
          'message',
          contains('Insecure HTTP'),
        )),
      );
    });
  });
}
