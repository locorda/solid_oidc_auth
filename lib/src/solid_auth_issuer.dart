import 'dart:async';

import 'package:http/http.dart' as http;
import 'package:locorda_rdf_core/core.dart';

const _solidOidcIssuer = 'http://www.w3.org/ns/solid/terms#oidcIssuer';

/// Extracts the `solid:oidcIssuer` from a WebID profile document, or returns
/// the input URI unchanged when it does not look like a WebID profile URL.
///
/// Throws [ArgumentError] if [textUrl] uses a non-HTTPS scheme on a non-local
/// host, or if the fetched profile contains no `solid:oidcIssuer` triple.
Future<String> getIssuer(String textUrl) async {
  if (textUrl.contains('profile/card#me')) {
    _assertSecureUrl(textUrl);
    final profileBody = await fetchProfileData(textUrl);
    return getIssuerUri(profileBody, textUrl);
  }

  // Treat the input as a direct issuer URI — validate it is a usable absolute URI.
  final uri = Uri.tryParse(textUrl);
  if (uri == null || !uri.hasScheme) {
    throw ArgumentError('Invalid issuer URI: $textUrl');
  }
  return textUrl;
}

/// Fetches the Turtle profile document at [profUrl].
///
/// Sends `Accept: text/turtle` so the server returns Turtle even when it
/// supports multiple RDF serialisations.
Future<String> fetchProfileData(String profUrl) async {
  final response = await http.get(
    Uri.parse(profUrl),
    headers: const {'Accept': 'text/turtle'},
  );

  if (response.statusCode == 200) {
    return response.body;
  }
  throw Exception(
    'Failed to load profile from $profUrl (HTTP ${response.statusCode}).',
  );
}

/// Parses [profileTurtle] as a Turtle document and extracts the first
/// `solid:oidcIssuer` object for [webId].
///
/// Throws [ArgumentError] when no `solid:oidcIssuer` triple is found.
String getIssuerUri(String profileTurtle, String webId) {
  final graph = turtle.decode(profileTurtle);
  final triples = graph.findTriples(
    subject: IriTerm(webId),
    predicate: const IriTerm(_solidOidcIssuer),
  );
  if (triples.isEmpty) {
    throw ArgumentError(
      'No solid:oidcIssuer found in profile for WebID <$webId>.',
    );
  }
  final object = triples.first.object;
  if (object is! IriTerm) {
    throw ArgumentError(
      'solid:oidcIssuer value is not an IRI for WebID <$webId>.',
    );
  }
  return object.value;
}

/// Throws [ArgumentError] if [url] uses HTTP on a non-local host.
///
/// Localhost variants (localhost, 127.0.0.1, [::1]) are allowed over plain
/// HTTP to support local development servers (e.g. Community Solid Server).
void _assertSecureUrl(String url) {
  final uri = Uri.parse(url);
  if (uri.scheme == 'https') return;
  if (uri.scheme == 'http') {
    final host = uri.host.toLowerCase();
    if (host == 'localhost' || host == '127.0.0.1' || host == '[::1]') return;
    throw ArgumentError(
      'Insecure HTTP is not permitted for non-local WebID profile URLs. '
      'Use HTTPS: $url',
    );
  }
}
