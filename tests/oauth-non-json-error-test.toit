// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import expect show *
import http
import log
import net

import oauth show *

import .test-helper_

main:
  test-non-json-error-surfaces-status

/**
If the token endpoint returns a non-2xx status with a body that is not valid
  JSON (for example an HTML error page from an upstream proxy), the client
  should surface the HTTP status rather than masking it with a parse error.
*/
test-non-json-error-surfaces-status:
  network := net.open
  socket := network.tcp-listen 0
  port := socket.local-address.port

  server := http.Server --logger=(log.default.with-level log.FATAL-LEVEL)
  task --background::
    server.listen socket:: | request/http.RequestIncoming writer/http.ResponseWriter |
      request.body.drain
      writer.write-headers 503 --message="Service Unavailable"
      writer.out.write "<html><body>upstream proxy error</body></html>"

  expired-ms := (Time.now - (Duration --s=10)).ms-since-epoch
  storage := TestLocalStorage --initial={
    "access_token": "AT-1",
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

  caught/AuthException? := null
  exception := catch:
    oauth-client.ensure-authenticated --network=network: | _ _ |
      throw "block should not be invoked"
  if exception is AuthException:
    caught = exception as AuthException

  expect-not-null caught
  expect-equals 503 caught.status-code
  expect-equals "Service Unavailable" caught.status-message

  socket.close
  network.close
