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
  test-state-mismatch-then-match

test-state-mismatch-then-match:
  network := net.open
  socket := network.tcp-listen 0
  port := socket.local-address.port

  token-call-count := 0

  server := http.Server --logger=(log.default.with-level log.FATAL-LEVEL)
  task --background::
    server.listen socket:: | request/http.RequestIncoming writer/http.ResponseWriter |
      request.body.drain
      if request.query.resource == "/token":
        token-call-count++
        writer.write-headers 200
        writer.out.write (json.encode {
          "access_token": "AT-1",
          "token_type": "bearer",
          "expires_in": 3600,
        })
      else:
        writer.write-headers 404
        writer.out.write "not found"

  storage := TestLocalStorage
  oauth-client := OAuth.localhost
      --client-id="my-client"
      --client-secret="my-secret"
      --endpoint="http://localhost:$port/authorize"
      --token-url="http://localhost:$port/token"
      --root-certificates=[]
      --scopes=["scope1"]
      --redirect-path="/cb"
      --local-storage=storage

  auth-url-latch := monitor.Latch
  done-latch := monitor.Latch
  task::
    oauth-client.ensure-authenticated --network=network: | authn-url _ |
      auth-url-latch.set authn-url
    done-latch.set true

  auth-url := auth-url-latch.get
  parsed := url.QueryString.parse auth-url
  state := parsed.parameters.get "state"
  expect-not-null state  // Client must generate a state for CSRF protection.
  redirect-uri := parsed.parameters["redirect_uri"]

  // First send a redirect with the wrong state.
  client := http.Client network
  bad-response := client.get --uri="$redirect-uri?code=fake-code&state=wrong-state"
  bad-response.body.read-all
  expect-not-equals 200 bad-response.status-code
  client.close

  // The token endpoint must not have been hit.
  expect-equals 0 token-call-count
  expect-not oauth-client.is-authenticated

  // Now send the correct state — auth should complete.
  client2 := http.Client network
  good-response := client2.get --uri="$redirect-uri?code=fake-code&state=$state"
  good-response.body.read-all
  expect-equals 200 good-response.status-code
  client2.close

  expect-equals true done-latch.get
  expect-equals 1 token-call-count
  expect oauth-client.is-authenticated

  socket.close
  network.close
