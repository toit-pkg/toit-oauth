# OAuth

An OAuth 2.0 authentication client for [Toit](https://toitlang.org/), supporting
the **authorization code flow** (with a localhost redirect) and the **device
authorization grant** flow.

The library handles the full token lifecycle: it drives the user through the
authentication flow, exchanges the result for an access token, refreshes the
token when it expires, and persists the token through a pluggable
[LocalStorage](src/oauth.toit) interface so the user does not have to log in
again on the next run.

## Flows

### Localhost code flow (`OAuth.localhost`)
Best for desktop applications that can open a browser. The library starts a
local HTTP server, asks the user to open an authorization URL, waits for the
provider to redirect back to `http://localhost:<port>/<path>`, and exchanges
the returned code for a token. The redirect URL must be registered with the
OAuth provider — most providers allow the port to vary, but not the host or
path.

### Device flow (`OAuth.device`)
Best for headless or embedded devices that cannot open a browser. The library
asks the provider for a verification URL and a short user code, surfaces them
to the user, and polls the token endpoint until the user completes the
authorization on a different device. This flow does not use a client secret.

## Quick start

The example below uses the localhost code flow with GitHub. See
[examples/](examples/) for:
- [localhost.toit](examples/localhost.toit) — GitHub authorization code flow.
- [device.toit](examples/device.toit) — Google device flow.
- [file-storage.toit](examples/file-storage.toit) — a file-backed
  `LocalStorage` implementation.
- [fake-server-flow.toit](examples/fake-server-flow.toit) — end-to-end device
  flow against an in-process fake provider; runs without credentials and is
  useful for trying the API.

```toit
import certificate-roots
import oauth

main:
  certificate-roots.install-common-trusted-roots

  client := oauth.OAuth.localhost
      --client-id="<your-client-id>"
      --client-secret="<your-client-secret>"
      --endpoint="https://github.com/login/oauth/authorize"
      --token-url="https://github.com/login/oauth/access_token"
      --redirect-path="/callback"
      --root-certificates=certificate-roots.ALL
      --scopes=["read:user"]
      --local-storage=oauth.NoLocalStorage

  client.ensure-authenticated: | url _ |
    print "Open this URL in your browser to authenticate:"
    print url
    oauth.open-browser url

  // The client now has a valid access token.
  print client.auth-headers
```

The block passed to `ensure-authenticated` is only invoked when the library
needs the user to take action (typically the first run, or when a refresh
token has been invalidated). On subsequent runs, a token loaded from
`LocalStorage` is reused — if it is expired and a refresh token is available,
the library refreshes it silently.

## LocalStorage

Tokens are persisted through the
[`LocalStorage`](src/oauth.toit) interface. The library ships with
`NoLocalStorage`, which discards everything (useful in tests or one-shot
tools). For real applications you should provide an implementation that writes
to a file, a config store, or a secure keychain. See
[examples/file-storage.toit](examples/file-storage.toit) for a simple
file-backed implementation.

## Error handling

OAuth errors raised by this library are instances of
[`AuthException`](src/oauth.toit). When a refresh fails (for example, because
the user revoked the grant), `ensure-authenticated` throws — clear the token
from `LocalStorage` and re-authenticate.

## References
- RFC 6749 — [The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- RFC 8628 — [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
