import 'dart:async';

import 'package:http/http.dart' as http;
import 'package:locorda_rdf_core/core.dart';

const _solidOidcIssuer = 'http://www.w3.org/ns/solid/terms#oidcIssuer';

/// RDF content types accepted when fetching WebID profiles.
///
/// The Solid Protocol mandates Turtle support on all servers; N-Triples is
/// added as a widely-implemented, line-based fallback. JSON-LD requires the
/// separate `locorda_rdf_jsonld` package and a custom [RdfCore] instance.
const _profileAcceptHeader = 'text/turtle, application/n-triples;q=0.9';

/// Extracts all `solid:oidcIssuer` IRIs from a WebID profile document, or
/// wraps the input URI in a single-element list when it does not look like a
/// WebID profile URL.
///
/// A URL is treated as a WebID profile when it is an HTTPS URL containing a
/// fragment identifier (`#`). This covers the Community Solid Server convention
/// (`/profile/card#me`) as well as any other WebID URL pattern
/// (`/webid#alice`, `/people/alice#me`, etc.). URLs without a fragment are
/// treated as direct issuer URIs.
///
/// An optional [rdfCore] instance customises parsing — e.g. non-standard
/// Turtle flags via [RdfCore.withCodecs], or JSON-LD support by registering
/// `locorda_rdf_jsonld` codecs. Defaults to the standard [rdf] global.
///
/// Throws [ArgumentError] if [textUrl] uses a non-HTTPS scheme on a non-local
/// host, or if the fetched profile contains no `solid:oidcIssuer` IRI triple.
Future<List<Uri>> getIssuers(
  String textUrl, {
  http.Client? httpClient,
  RdfCore? rdfCore,
}) async {
  final uri = Uri.tryParse(textUrl);
  if (uri != null && uri.hasFragment) {
    _assertSecureUrl(textUrl);
    final result = await _fetchRaw(textUrl, httpClient: httpClient);
    return getIssuerUris(
      result.body,
      textUrl,
      contentType: result.contentType,
      rdfCore: rdfCore,
    ).map(Uri.parse).toList();
  }

  // Treat the input as a direct issuer URI — validate it is a usable absolute URI.
  if (uri == null || !uri.hasScheme) {
    throw ArgumentError('Invalid issuer URI: $textUrl');
  }
  return [uri];
}

/// Fetches the RDF profile document at [profUrl] and returns its body.
///
/// An optional [httpClient] can be supplied for testing; when omitted a
/// temporary [http.Client] is created and closed after the single request.
Future<String> fetchProfileData(
  String profUrl, {
  http.Client? httpClient,
}) async {
  final result = await _fetchRaw(profUrl, httpClient: httpClient);
  return result.body;
}

/// Parses [profileBody] as an RDF document and extracts all
/// `solid:oidcIssuer` IRI values for [webId].
///
/// Non-IRI values (e.g. literals) are silently ignored; only well-formed
/// IRI objects are returned. The Solid spec requires IRIs here, so a
/// literal value indicates a malformed profile.
///
/// [contentType] selects the deserialiser and defaults to `text/turtle`.
/// An optional [rdfCore] allows injecting a custom codec configuration —
/// e.g. [RdfCore.withCodecs] with a [TurtleCodec] configured for lenient
/// parsing, or an instance extended with JSON-LD support.
///
/// Throws [ArgumentError] when no `solid:oidcIssuer` IRI is found.
List<String> getIssuerUris(
  String profileBody,
  String webId, {
  String contentType = 'text/turtle',
  RdfCore? rdfCore,
}) {
  final effectiveRdf = rdfCore ?? rdf;
  final graph = effectiveRdf.decode(
    profileBody,
    contentType: contentType,
    documentUrl: webId,
  );
  final issuers = graph
      .findTriples(
        subject: IriTerm(webId),
        predicate: const IriTerm(_solidOidcIssuer),
      )
      .map((t) => t.object)
      .whereType<IriTerm>()
      .map((iri) => iri.value)
      .toList();
  if (issuers.isEmpty) {
    throw ArgumentError(
      'No solid:oidcIssuer IRI found in profile for WebID <$webId>.',
    );
  }
  return issuers;
}

/// Fetches [profUrl] and returns the response body together with its
/// media type (stripped of parameters, e.g. `text/turtle`).
///
/// Sends [_profileAcceptHeader] to trigger content negotiation. Ownership of
/// [httpClient] is not transferred: when omitted, a temporary client is
/// created and closed after the request.
Future<({String body, String contentType})> _fetchRaw(
  String profUrl, {
  http.Client? httpClient,
}) async {
  final client = httpClient ?? http.Client();
  final bool owned = httpClient == null;
  try {
    final response = await client.get(
      Uri.parse(profUrl),
      headers: const {'Accept': _profileAcceptHeader},
    );
    if (response.statusCode != 200) {
      throw Exception(
        'Failed to load profile from $profUrl (HTTP ${response.statusCode}).',
      );
    }
    final ct = response.headers['content-type']?.split(';').first.trim() ??
        'text/turtle';
    return (body: response.body, contentType: ct);
  } finally {
    if (owned) client.close();
  }
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
    if (host == 'localhost' || host == '127.0.0.1' || host == '::1') return;
    throw ArgumentError(
      'Insecure HTTP is not permitted for non-local WebID profile URLs. '
      'Use HTTPS: $url',
    );
  }
}
