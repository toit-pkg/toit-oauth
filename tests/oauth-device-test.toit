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
  test-device-happy-path

test-device-happy-path:
  network := net.open
  socket := network.tcp-listen 0
  port := socket.local-address.port

  poll-count := 0
  endpoint-call-count := 0

  server := http.Server --logger=(log.default.with-level log.FATAL-LEVEL)
  task --background::
    server.listen socket:: | request/http.RequestIncoming writer/http.ResponseWriter |
      request.body.drain
      if request.path == "/device":
        endpoint-call-count++
        body := json.encode {
          "device_code": "DC-1",
          "user_code": "USER123",
          "verification_uri": "http://localhost:$port/verify",
          "expires_in": 60,
          "interval": 0,
        }
        writer.write-headers 200
        writer.out.write body
      else if request.path == "/token":
        poll-count++
        if poll-count == 1:
          // First poll: not yet authorized.
          writer.write-headers 400
          writer.out.write (json.encode { "error": "authorization_pending" })
        else:
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
  oauth-client := OAuth.device
      --client-id="my-client"
      --endpoint-url="http://localhost:$port/device"
      --token-url="http://localhost:$port/token"
      --root-certificates=[]
      --scopes=["scope1"]
      --local-storage=storage

  received-uri/string? := null
  received-code/string? := null
  oauth-client.ensure-authenticated --network=network: | uri code |
    received-uri = uri
    received-code = code

  expect-equals "http://localhost:$port/verify" received-uri
  expect-equals "USER123" received-code

  expect-equals 1 endpoint-call-count
  expect-equals 2 poll-count  // One pending, then success.

  expect oauth-client.is-authenticated
  expect-equals "Bearer AT-1" oauth-client.auth-headers["Authorization"]

  socket.close
  network.close
