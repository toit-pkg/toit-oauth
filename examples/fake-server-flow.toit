// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import encoding.json
import http
import log
import net
import oauth

/**
Example: end-to-end device flow against a fake in-process OAuth server.

Unlike the other examples, this one runs without any external credentials
  or network access. It boots a tiny HTTP server that mimics the device
  authorization grant endpoints, then drives $oauth.OAuth.device against it.
  The output shows the user-facing prompt the library produces, and the
  resulting authorization header.

Run with: `toit examples/fake-server-flow.toit`
*/

main:
  network := net.open
  socket := network.tcp-listen 0
  port := socket.local-address.port

  poll-count := 0
  server := http.Server --logger=(log.default.with-level log.FATAL-LEVEL)
  task --background::
    server.listen socket:: | request/http.RequestIncoming writer/http.ResponseWriter |
      request.body.drain
      if request.path == "/device":
        // First step: hand out a device code.
        writer.write-headers 200
        writer.out.write (json.encode {
          "device_code": "device-abc",
          "user_code": "WXYZ-1234",
          "verification_uri": "http://localhost:$port/verify",
          "expires_in": 60,
          "interval": 0,  // No delay between polls so the example is fast.
        })
      else if request.path == "/token":
        // Second step: pretend to be pending once, then hand out a token.
        poll-count++
        if poll-count == 1:
          writer.write-headers 400
          writer.out.write (json.encode { "error": "authorization_pending" })
        else:
          writer.write-headers 200
          writer.out.write (json.encode {
            "access_token": "pretend-access-token",
            "token_type": "bearer",
            "expires_in": 3600,
          })

  client := oauth.OAuth.device
      --client-id="example-client"
      --endpoint-url="http://localhost:$port/device"
      --token-url="http://localhost:$port/token"
      --root-certificates=[]  // Empty list disables TLS — fine for plain HTTP.
      --scopes=["read"]
      --local-storage=oauth.NoLocalStorage

  client.ensure-authenticated --network=network: | url code |
    print "On another device, open: $url"
    print "Then enter the code: $code"

  print "Authenticated."
  print "Authorization header: $client.auth-headers"

  socket.close
  network.close
