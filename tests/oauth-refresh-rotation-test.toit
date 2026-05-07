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
  test-refresh-token-preserved-when-omitted

/**
Some providers (notably Google) only issue a refresh token on the very first
  exchange and omit it from subsequent refresh responses. The client must
  carry the previous refresh token forward instead of replacing it with null.
*/
test-refresh-token-preserved-when-omitted:
  network := net.open
  socket := network.tcp-listen 0
  port := socket.local-address.port

  // Each entry captures the body of one /token request as a Map.
  refresh-bodies := []

  server := http.Server --logger=(log.default.with-level log.FATAL-LEVEL)
  task --background::
    server.listen socket:: | request/http.RequestIncoming writer/http.ResponseWriter |
      body := json.decode-stream request.body
      if request.path == "/token":
        refresh-bodies.add body
        // Note: response omits refresh_token entirely.
        writer.write-headers 200
        writer.out.write (json.encode {
          "access_token": "AT-new-$refresh-bodies.size",
          "token_type": "bearer",
          "expires_in": 1,  // Short-lived so we can trigger refresh again.
        })
      else:
        writer.write-headers 404
        writer.out.write "not found"

  expired-ms := (Time.now - (Duration --s=10)).ms-since-epoch
  storage := TestLocalStorage --initial={
    "access_token": "AT-original",
    "token_type": "bearer",
    "expires_at_epoch_ms": expired-ms,
    "refresh_token": "RT-1",
  }

  oauth-client := OAuth.device
      --client-id="my-client"
      --endpoint-url="http://localhost:$port/device"
      --token-url="http://localhost:$port/token"
      --root-certificates=[]
      --scopes=["scope1"]
      --local-storage=storage

  // First refresh.
  oauth-client.ensure-authenticated --network=network: | _ _ |
    throw "block should not be invoked"

  expect-equals 1 refresh-bodies.size
  expect-equals "RT-1" refresh-bodies[0]["refresh_token"]
  expect oauth-client.is-authenticated

  // Force the new access token to be considered expired and refresh again.
  // The just-stored token has expires_in=1; sleep just over that.
  sleep --ms=1100
  expect-not oauth-client.is-authenticated

  // Second refresh should still use RT-1 (the original), since the server
  // omitted refresh_token from the previous response.
  oauth-client.ensure-authenticated --network=network: | _ _ |
    throw "block should not be invoked"

  expect-equals 2 refresh-bodies.size
  expect-equals "RT-1" refresh-bodies[1]["refresh_token"]
  expect oauth-client.is-authenticated

  socket.close
  network.close
