// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import certificate-roots
import http
import net
import oauth

/**
Example: localhost (authorization code) flow with GitHub.

Replace $CLIENT-ID and $CLIENT-SECRET with values from a registered GitHub
  OAuth app (https://github.com/settings/developers). The app's "Authorization
  callback URL" must be registered as `http://localhost/callback` — GitHub
  allows the port to vary, so the random port chosen by this program will
  match.

After authentication this program prints the authenticated user's GitHub
  login by calling the GitHub API with the obtained bearer token.
*/

CLIENT-ID     ::= "<your-github-client-id>"
CLIENT-SECRET ::= "<your-github-client-secret>"

main:
  client := oauth.OAuth.localhost
      --client-id=CLIENT-ID
      --client-secret=CLIENT-SECRET
      --endpoint="https://github.com/login/oauth/authorize"
      --token-url="https://github.com/login/oauth/access_token"
      --redirect-path="/callback"
      --root-certificates=certificate-roots.ALL
      --scopes=["read:user"]
      --local-storage=oauth.NoLocalStorage

  // The block is only invoked when the user must authenticate. On subsequent
  // runs, a token persisted in `LocalStorage` (or refreshed via its refresh
  // token) is reused silently.
  client.ensure-authenticated: | url _ |
    print "Open this URL to authenticate:"
    print url
    oauth.open-browser url

  // Use the bearer token to call an API.
  network := net.open
  http-client := http.Client.tls network --root-certificates=certificate-roots.ALL
  headers := http.Headers
  client.auth-headers.do: | name value | headers.add name value
  headers.add "User-Agent" "toit-oauth-example"
  headers.add "Accept" "application/vnd.github+json"

  response := http-client.get --uri="https://api.github.com/user" --headers=headers
  print response.body.read-all.to-string
  http-client.close
  network.close
