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
  test-device-poll-http-error

/**
If the token endpoint returns an unexpected HTTP error (not the standard
  authorization_pending / slow_down / expired_token JSON), the device flow
  should surface it instead of silently looping forever.
*/
test-device-poll-http-error:
  network := net.open
  socket := network.tcp-listen 0
  port := socket.local-address.port

  poll-count := 0

  server := http.Server --logger=(log.default.with-level log.FATAL-LEVEL)
  task --background::
    server.listen socket:: | request/http.RequestIncoming writer/http.ResponseWriter |
      request.body.drain
      if request.path == "/device":
        writer.write-headers 200
        writer.out.write (json.encode {
          "device_code": "DC-1",
          "user_code": "USER123",
          "verification_uri": "http://localhost:$port/verify",
          "expires_in": 60,
          "interval": 0,
        })
      else if request.path == "/token":
        poll-count++
        writer.write-headers 502 --message="Bad Gateway"
        writer.out.write "<html>upstream proxy error</html>"
      else:
        writer.write-headers 404
        writer.out.write "not found"

  storage := TestLocalStorage
  oauth-client := OAuth.device
      --client-id="my-client"
      --endpoint-url="http://localhost:$port/device"
      --token-url="http://localhost:$port/token"
      --root-certificates=[]
      --scopes=["scope1"]
      --local-storage=storage

  caught/AuthException? := null
  exception := catch:
    oauth-client.ensure-authenticated --network=network: | _ _ |
      null  // Block invocation is fine; user-code presentation isn't the issue.
  if exception is AuthException:
    caught = exception as AuthException

  expect-not-null caught
  expect-equals 502 caught.status-code
  // Should have polled exactly once and given up, not looped silently.
  expect-equals 1 poll-count

  socket.close
  network.close
