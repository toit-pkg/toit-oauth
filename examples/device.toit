// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import certificate-roots
import oauth

/**
Example: device flow with Google.

The device flow is the right choice for headless or embedded devices that
  cannot open a browser. The device displays a verification URL and a short
  user code; the user opens the URL on a phone or laptop and enters the code
  to authorize the application.

Set up: create OAuth 2.0 client credentials of type "TVs and Limited Input
  devices" in the Google Cloud Console and put the client ID below.

The endpoint and token URLs are taken from Google's OpenID discovery document
  at https://accounts.google.com/.well-known/openid-configuration.
*/

CLIENT-ID ::= "<your-google-client-id>"

main:
  client := oauth.OAuth.device
      --client-id=CLIENT-ID
      --endpoint-url="https://oauth2.googleapis.com/device/code"
      --token-url="https://oauth2.googleapis.com/token"
      --root-certificates=certificate-roots.ALL
      --scopes=["https://www.googleapis.com/auth/userinfo.email"]
      --local-storage=oauth.NoLocalStorage

  client.ensure-authenticated: | url code |
    print "On another device, open: $url"
    print "Then enter the code: $code"

  print "Authenticated. Authorization header:"
  print client.auth-headers
