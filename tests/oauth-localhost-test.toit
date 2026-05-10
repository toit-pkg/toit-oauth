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
  test-localhost-happy-path

test-localhost-happy-path:
  network := net.open
  socket := network.tcp-listen 0
  port := socket.local-address.port

  received-token-params/Map? := null

  server := http.Server --logger=(log.default.with-level log.FATAL-LEVEL)
  task --background::
    server.listen socket:: | request/http.RequestIncoming writer/http.ResponseWriter |
      request.body.drain
      if request.query.resource.starts-with "/token":
        received-token-params = request.query.parameters
        body := json.encode {
          "access_token": "AT-1",
          "token_type": "bearer",
          "refresh_token": "RT-1",
          "expires_in": 3600,
        }
        writer.write-headers 200
        writer.out.write body
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
  expect-equals "my-client" parsed.parameters["client_id"]
  expect-equals "scope1" parsed.parameters["scope"]
  expect-equals "code" parsed.parameters["response_type"]
  redirect-uri := parsed.parameters["redirect_uri"]

  // Simulate the user being redirected with a code.
  client := http.Client network
  response := client.get --uri="$redirect-uri?code=fake-code"
  expect-equals 200 response.status-code
  response.body.read-all  // Drain.
  client.close

  expect-equals true done-latch.get

  expect-not-null received-token-params
  expect-equals "fake-code" received-token-params["code"]
  expect-equals "my-client" received-token-params["client_id"]
  expect-equals "my-secret" received-token-params["client_secret"]
  expect-equals "authorization_code" received-token-params["grant_type"]

  expect oauth-client.is-authenticated
  expect-equals "Bearer AT-1" oauth-client.auth-headers["Authorization"]

  // Storage should have persisted the token.
  expect storage.has-auth
  expect-equals "AT-1" storage.get-auth["access_token"]
  expect-equals "RT-1" storage.get-auth["refresh_token"]

  socket.close
  network.close
