// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import crypto
import encoding.hex
import encoding.json
import encoding.url
import http
import log
import monitor
import net
import net.tcp

import .oauth
import .token
import .utils_

class DeviceOAuth_ extends OAuth:
  endpoint-url_/string

  /** See $OAuth.device. */
  constructor
      --client-id/string
      --endpoint-url/string
      --token-url/string
      --root-certificates/List
      --scopes/List
      --local-storage/LocalStorage:
    endpoint-url_ = endpoint-url
    super.from-sub_
        --client-id=client-id
        --client-secret=null
        --token-url=token-url
        --scopes=scopes
        --root-certificates=root-certificates
        --local-storage=local-storage

  do-authentication_ --network/net.Client?=null [block] -> Token:
    with-http-client network --root-certificates=root-certificates_: | client/http.Client |
      headers := http.Headers
      headers.add "Accept" "application/json"
      response := client.post-form --uri=endpoint-url_ --headers=headers {
        "client_id": client-id_,
        "scope": scopes_.join " ",
      }
      decoded/Map := {:}
      exception := catch:
        decoded = json.decode-stream response.body
      if response.status-code != 200 or exception:
        throw (AuthException
            --status-code=response.status-code
            --status-message=response.status-message
            --error-code=decoded.get "error"
            --error-description=decoded.get "error_description")

      device-code := decoded["device_code"]
      user-code := decoded["user_code"]
      verification-uri := decoded["verification_uri"]
      expires-in-s :=decoded["expires_in"]
      interval-s := decoded["interval"]

      block.call verification-uri user-code

      expires-time := Time.now + (Duration --s=expires-in-s)
      while Time.now < expires-time:
        sleep --ms=(1000 * interval-s)

        // Check if the user has authorized the application.
        response = client.post-json --uri=token-url_ --headers=headers {
          "client_id": client-id_,
          "device_code": device-code,
          "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }

        decoded = {:}
        exception = catch:
          decoded = json.decode-stream response.body

        if decoded.contains "access_token":
          return parse-token-json_ decoded

        error-code := decoded.get "error"

        if error-code == "authorization_pending":
          // Still waiting for the user to authorize the application.
          continue

        if error-code == "slow_down":
          // We have to wait longer between intervals.
          if decoded.contains "interval":
            interval-s = decoded["interval"]
          else:
            interval-s += 5
          continue

        if error-code == "expired_token":
          // Shouldn't really happen since we only poll as long as
          // the token is valid.
          break

        // Anything else (unexpected error code, non-2xx status, unparseable
        // body) is unrecoverable — surface it instead of silently looping.
        throw (AuthException
            --status-code=response.status-code
            --status-message=response.status-message
            --error-code=error-code
            --error-description=decoded.get "error_description")

      // TODO(florian): is this a good error?
      throw DEADLINE-EXCEEDED-ERROR
    unreachable

/**
An OAuth authorization code flow.
*/
class LocalhostCodeOAuth_ extends OAuth:
  localhost_/string
  redirect-path_/string
  logger_/log.Logger
  endpoint_/string
  query-parameters_/Map

  /**
  See $OAuth.localhost.
  */
  constructor
      --localhost/string="localhost"
      --redirect-path/string
      --logger/log.Logger=(log.default.with-level log.FATAL-LEVEL)
      --endpoint/string
      --client-id/string
      --client-secret/string
      --scopes/List
      --token-url/string
      --root-certificates/List
      --query-parameters/Map={:}
      --local-storage/LocalStorage:
    localhost_ = localhost
    redirect-path_ = redirect-path
    logger_ = logger
    endpoint_ = endpoint
    query-parameters_ = query-parameters

    super.from-sub_
        --client-id=client-id
        --client-secret=client-secret
        --token-url=token-url
        --scopes=scopes
        --root-certificates=root-certificates
        --local-storage=local-storage

  do-authentication_ --network/net.Client?=null [block] -> Token:
    network-needs-close := false
    if not network:
      network = net.open
      network-needs-close = true

    server-socket/tcp.ServerSocket? := null

    try:
      server-socket = network.tcp-listen 0
      server := http.Server --logger=logger_
      port := server-socket.local-address.port

      redirect-url := "http://$localhost_:$port$redirect-path_"

      code-flow := OAuthCodeFlow
          --client-id=client-id_
          --client-secret=client-secret_
          --token-url=token-url_
          --root-certificates=root-certificates_
          --endpoint=endpoint_
          --redirect-url=redirect-url
          --query-parameters=query-parameters_

      // Generate a random state string for CSRF protection.
      state := hex.encode (crypto.random --size=16)
      authenticate-url := code-flow.get-url --scopes=scopes_ state
      block.call authenticate-url null

      session-latch := monitor.Latch
      server-task := task::
        server.listen server-socket:: | request/http.Request writer/http.ResponseWriter |
          if request.path.starts-with redirect-path_ and request.path.contains "?":
            // TODO(florian): extract error if there is one:
            // ```
            // http://localhost:41055/auth?error=server_error&error_description=Database+error+saving+new+user
            // ```
            received-state := (url.QueryString.parse request.path).parameters.get "state"
            if received-state != state:
              writer.write-headers 400
              writer.out.write "Invalid state parameter."
            else:
              token := code-flow.get-token request.path --network=network
              writer.out.write "You can close this window now."
              session-latch.set token
          else if request.path.starts-with redirect-path_:
            // No query parameters.
            // The information might be in the fragment (hash) data.
            // Send a web-page that changes the fragment to a query string.
            writer.out.write """
            <html>
              <body>
                <p id="body">
                This page requires JavaScript to continue.
                </p>
                <script type="text/javascript">
                  const req = new XMLHttpRequest();
                  req.addEventListener("load", function() {
                    document.getElementById("body").innerHTML = "You can close this window now.";
                  });
                  req.open("GET", "http://localhost:$port/$redirect-path_?" window.location.hash.substring(1));
                  req.send();
                  document.getElementById("body").innerHTML = "Transmitting data to CLI...";
                </script>
              </body>
            </html>
            """
          else:
            writer.out.write "Invalid request."

      result := session-latch.get
      sleep --ms=1  // Give the server time to respond with the success message.
      server-task.cancel
      return result
    finally:
      if server-socket:
        server-socket.close
      if network-needs-close:
        network.close
