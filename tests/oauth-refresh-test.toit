// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import encoding.json
import expect show *
import http
import log
import net

import oauth show *

import .test-helper_

main:
  test-refresh-happy-path

test-refresh-happy-path:
  network := net.open
  socket := network.tcp-listen 0
  port := socket.local-address.port

  received-body/Map? := null

  server := http.Server --logger=(log.default.with-level log.FATAL-LEVEL)
  task --background::
    server.listen socket:: | request/http.RequestIncoming writer/http.ResponseWriter |
      received-body = json.decode-stream request.body
      if request.path == "/token":
        writer.write-headers 200
        writer.out.write (json.encode {
          "access_token": "AT-2",
          "token_type": "bearer",
          "refresh_token": "RT-2",
          "expires_in": 3600,
        })
      else:
        writer.write-headers 404
        writer.out.write "not found"

  // Pre-seed storage with an expired access token plus a refresh token.
  expired-ms := (Time.now - (Duration --s=10)).ms-since-epoch
  initial-token := {
    "access_token": "AT-1",
    "token_type": "bearer",
    "expires_at_epoch_ms": expired-ms,
    "refresh_token": "RT-1",
  }
  storage := TestLocalStorage --initial=initial-token

  oauth-client := OAuth.device
      --client-id="my-client"
      --endpoint-url="http://localhost:$port/device"
      --token-url="http://localhost:$port/token"
      --root-certificates=[]
      --scopes=["scope1"]
      --local-storage=storage

  // Token is expired but exists, so ensure-authenticated should refresh.
  expect-not oauth-client.is-authenticated

  oauth-client.ensure-authenticated --network=network: | _ _ |
    throw "block should not be invoked when refresh succeeds"

  expect oauth-client.is-authenticated
  expect-equals "Bearer AT-2" oauth-client.auth-headers["Authorization"]

  // Verify the refresh request had the right fields.
  expect-not-null received-body
  expect-equals "RT-1" received-body["refresh_token"]
  expect-equals "refresh_token" received-body["grant_type"]
  expect-equals "my-client" received-body["client_id"]

  // Storage should now hold the new tokens.
  expect-equals "AT-2" storage.get-auth["access_token"]
  expect-equals "RT-2" storage.get-auth["refresh_token"]

  socket.close
  network.close
