## [0.2.0]

This is a ground-up rewrite by [Locorda](https://locorda.dev), forked from
[anusii/solid_auth](https://github.com/anusii/solid_auth). The history of the
original package is preserved in [CHANGELOG_INHERITED.md](CHANGELOG_INHERITED.md).

### Breaking Changes

* Package renamed from `solid_auth` to `solid_oidc_auth`
* Entry point changed to `package:solid_oidc_auth/solid_oidc_auth.dart`
* Worker entry point introduced as `package:solid_oidc_auth/worker.dart`
* Completely new public API — `SolidOidcAuth`, `SolidOidcAuthSettings`,
  `SolidOidcAuthUriSettings` replace the old `authenticate()` / `getIssuer()` /
  `genDpopToken()` top-level functions
* Authentication now requires a [Public Client Identifier Document](https://solid.github.io/solid-oidc/#clientids-document)
  (client-profile.jsonld) instead of a loopback redirect URI
* Minimum SDK constraint tightened to `>=3.0.0`

### Architecture

* Replaced all embedded source copies (`openid_client`, `dart_jsonwebtoken`,
  `pointycastle`) with upstream dependencies
* OIDC layer now built on the certified [`oidc`](https://pub.dev/packages/oidc)
  package by BdayaDev, which handles token lifecycle, refresh, and secure storage
* RSA key management decoupled behind `RsaApi` interface; backed by
  [`fast_rsa`](https://pub.dev/packages/fast_rsa) for native platforms and a
  pure-Dart fallback for web/isolates
* WebID-to-issuer resolution extracted into a standalone, testable
  `SolidAuthIssuer` component (RDF-based, via `locorda_rdf_core`)
* `DpopCredentials` value object provides serialisable, exportable credentials
  for use from web workers / isolates

### Security

* Loopback redirect (localhost) authentication is no longer supported or
  endorsed — uses the Solid-OIDC Client Identifier Document mechanism instead
* DPoP tokens now comply with RFC 9449 §4.2: `htu` claim supported
* WebID detection based on URI fragment (not `profile/card#me` string match),
  covering all spec-compliant WebID patterns
* HTTPS enforced for all non-localhost WebID profile fetches

### Other Changes

* Reactive authentication state via `ValueListenable<bool> isAuthenticatedNotifier`
* Session persistence: RSA key pair and authentication parameters survive app
  restarts without re-authentication
* `worker.dart` entry point for Flutter-free use in web workers / Dart isolates
* Removed `collection`, `url_launcher`, `flutter_web_auth_2`, `jose`,
  `openid_client`, `pointycastle`, `intl` dependencies
* Added `oidc`, `oidc_default_store`, `locorda_rdf_core`, `fast_rsa`,
  `dart_jsonwebtoken`, `logging`, `meta` dependencies

---

*For the history of the original `solid_auth` package (≤ 0.1.27),
see [CHANGELOG_INHERITED.md](CHANGELOG_INHERITED.md).*
