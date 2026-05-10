// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import encoding.json
import encoding.url
import expect show *
import http
import log
import monitor
import net

import oauth show *

import .test-helper_

main:
  test-fragment-redirect-html-is-valid

/**
When the OAuth provider returns the authorization response in the URL
  fragment (the part after #) instead of the query string, the local server
  serves a small HTML page that uses XHR to forward the fragment to itself
  as a query string. The HTML must contain syntactically valid JavaScript
  and a correctly-formed URL.
*/
test-fragment-redirect-html-is-valid:
  network := net.open
  socket := network.tcp-listen 0
  port := socket.local-address.port

  server := http.Server --logger=(log.default.with-level log.FATAL-LEVEL)
  task --background::
    server.listen socket:: | request/http.RequestIncoming writer/http.ResponseWriter |
      request.body.drain
      // Always serve a successful token response so the auth flow can finish.
      writer.write-headers 200
      writer.out.write (json.encode {
        "access_token": "AT-1",
        "token_type": "bearer",
        "expires_in": 3600,
      })

  storage := TestLocalStorage
  oauth-client := OAuth.localhost
      --client-id="my-client"
      --client-secret="my-secret"
      --endpoint="http://localhost:$port/authorize"
      --token-url="http://localhost:$port/token"
      --root-certificates=[]
      --scopes=["scope1"]
      --redirect-path="/callback"
      --local-storage=storage

  auth-url-latch := monitor.Latch
  done-latch := monitor.Latch
  task::
    oauth-client.ensure-authenticated --network=network: | authn-url _ |
      auth-url-latch.set authn-url
    done-latch.set true

  auth-url := auth-url-latch.get
  parsed := url.QueryString.parse auth-url
  redirect-uri := parsed.parameters["redirect_uri"]
  state := parsed.parameters["state"]

  // Hit the redirect URL WITHOUT a query string -- this triggers the
  // fragment-forwarding HTML page.
  client := http.Client network
  response := client.get --uri=redirect-uri
  expect-equals 200 response.status-code
  body-bytes := #[]
  while chunk := response.body.read:
    body-bytes += chunk
  body := body-bytes.to-string
  client.close

  // The JavaScript must concatenate the strings correctly. The buggy version
  // omits the '+' between the URL prefix and window.location.hash.
  expect (body.contains "+ window.location.hash.substring(1)")

  // The URL must not contain a double slash before the redirect path.
  expect-not (body.contains "//callback")

  // Finish the auth flow so the task terminates cleanly.
  client2 := http.Client network
  finish-response := client2.get --uri="$redirect-uri?code=fake-code&state=$state"
  finish-response.body.read-all
  client2.close

  expect-equals true done-latch.get

  socket.close
  network.close
