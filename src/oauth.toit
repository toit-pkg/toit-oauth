// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import encoding.url
import encoding.json
import http
import log
import net
import system
import host.pipe

import .flows_
import .token
import .utils_

/**
An authentication provider.

Authentication providers log in a user and provide the necessary information to
  authenticate requests.
*/
interface AuthProvider:
  /**
  Ensures that the user is authenticated.

  If the user is not authenticated, the $block is called with a URL the user
    should visit to authenticate. A second argument to $block provides
    a key the user has to enter at the URL. If the second argument is null,
    then the user does not have to enter a key.
  */
  ensure-authenticated [block] -> none

  /**
  The authentication headers for the current user.
  */
  auth-headers -> Map

  /**
  Whether the user is authenticated.

  Only looks at the local state, not at the server. If the server has
    invalidated the authentication, this will still return true.
  */
  is-authenticated -> bool

/**
An interface to store authentication information locally.

On desktops this should be the config file.
On mobile this could be something like HiveDB/Isar.
*/
interface LocalStorage:
  /**
  Whether the storage contains any authorization information.
  */
  has-auth -> bool

  /**
  Returns the stored authorization information.
  If none exists, returns null.
  */
  get-auth -> any?

  /**
  Sets the authorization information to $value.

  The $value must be JSON-encodable.
  */
  set-auth value/any -> none

  /**
  Removes any authorization information.
  */
  remove-auth -> none

/**
A simple implementation of $LocalStorage that simply discards all data.
*/
class NoLocalStorage implements LocalStorage:
  has-auth -> bool: return false
  get-auth -> any?: return null
  set-auth value/any: return
  remove-auth -> none: return

abstract class TokenAuthProvider implements AuthProvider:
  root-certificates_/List
  token_/Token? := null
  local-storage_/LocalStorage

  constructor --root-certificates/List --local-storage/LocalStorage:
    local-storage_ = local-storage
    root-certificates_ = root-certificates
    if local-storage_.has-auth:
      token_ = Token.from-json local-storage_.get-auth

  is-authenticated -> bool:
    return token_ != null and not token_.has-expired

  /** See $AuthProvider.ensure-authenticated. */
  ensure-authenticated --network/net.Client?=null [block] -> none:
    if is-authenticated: return
    if token_ != null:
      token_ = refresh token_ --network=network
      save_
      return

    token_ = do-authentication_ --network=network block
    save_

  /** See $AuthProvider.auth-headers. */
  auth-headers -> Map:
    if token_ == null: return {:}
    return token_.auth-headers

  save_ -> none:
    if token_ == null: throw "INVALID_STATE"
    local-storage_.set-auth token_.to-json

  abstract refresh --network/net.Client?=null token/Token -> Token
  abstract do-authentication_ --network/net.Client?=null [block] -> Token

class AuthException:
  status-code/int?
  status-message/string?
  error-code/string?
  error-description/string?

  constructor
      --.status-code=null
      --.status-message=null
      --.error-code=null
      --.error-description=null:

  /**
  Error descriptions for OAuth 2.0 errors.

  See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1.

  Also contains error descriptions for errors that are not part of the
    OAuth 2.0 specification, but are used by this library.
  */
  static ERROR-DESCRIPTIONS ::= {
    "invalid_request": """
      The request is missing a required parameter, includes an invalid \
      parameter value, includes a parameter more than once, or is otherwise \
      malformed.""",
    "unauthorized_client": """
      The client is not authorized to request an access token using this \
      method.""",
    "access_denied": """
      The resource owner or authorization server denied the request.""",
    "unsupported_response_type": """
      The authorization server does not support obtaining an access token \
      using this method.""",
    "invalid_scope": """
      The requested scope is invalid, unknown, or malformed.""",
    "server_error": """
      The authorization server encountered an unexpected condition that \
      prevented it from fulfilling the request.""",
    "temporarily_unavailable": """
      The authorization server is currently unable to handle the request \
      due to a temporary overloading or maintenance of the server.""",
    "missing_code": """
      The authorization server did not return an authorization code in the \
      response.""",
    "missing_access_token": """
      The token server did not return an access token in the response.""",
  }

  /**
  Converts a one-word error string to a human-readable error string.
  */
  static error-to-human error/string -> string:
    return ERROR-DESCRIPTIONS.get error --if-absent=: error

  stringify -> string:
    if error-code:
      return "$error-code: $error-description"
    if status-code:
      return "HTTP $status-code $status-message"
    return "Unknown error"

parse-token-response_ response/http.Response -> Token:
  decoded/Map := {:}
  exception := catch:
    decoded = json.decode-stream response.body

  // Surface HTTP errors before parse errors: a non-2xx status with a non-JSON
  // body (e.g. an HTML error page from an upstream proxy) is more informative
  // as "HTTP 503" than as "parse_error".
  if response.status-code != 200:
    throw (AuthException
        --status-code=response.status-code
        --status-message=response.status-message
        --error-code=decoded.get "error"
        --error-description=decoded.get "error_description")

  if exception:
    throw (AuthException
        --error-code="parse_error"
        --error-description="Failed to parse token response: $exception")

  return parse-token-json_ decoded

parse-token-json_ decoded/Map -> Token:
  access-token := decoded.get "access_token"
  token-type := decoded.get "token_type"
  expires-in := decoded.get "expires_in"
  refresh-token := decoded.get "refresh_token"
  scope := decoded.get "scope"
  returned-scopes := scope and (scope.split " ")

  if not access-token:
    throw (AuthException
        --error-code="missing_access_token"
        --error-description="The access token is missing")

  return Token
      --access-token=access-token
      --token-type=token-type
      --expires-in-s=expires-in
      --refresh-token=refresh-token
      --scopes=returned-scopes

/**
An OAuth client that uses a token endpoint to authenticate.
*/
abstract class OAuth extends TokenAuthProvider:
  token-url_/string
  client-id_/string
  client-secret_/string?

  scopes_/List

  constructor.from-sub_
      --client-id
      --client-secret
      --token-url
      --scopes
      --root-certificates/List
      --local-storage/LocalStorage:
    client-id_ = client-id
    client-secret_ = client-secret
    token-url_ = token-url
    scopes_ = scopes
    super --root-certificates=root-certificates --local-storage=local-storage

  /**
  Constructs an OAuth provider that uses a code flow redirecting to localhost.

  When doing the authentication ($ensure-authenticated), this instance will
    start a local http server that listens for a redirect from the OAuth provider.

  The $localhost parameter must be "localhost" or "127.0.0.1".
  The $redirect-path parameter is the path that the authenticated user should be
    redirected to. Typically, the OAuth provider has a list of valid redirect
    URLs (including the paths), and the combined URI ($localhost + $redirect-path)
    must be one of them. Most OAuth providers allow to change the port of a localhost
    redirect URL, but not the host name or the path.

  The $client-id is provided by the OAuth provider and identifies the application.
  The $client-secret is generated by the OAuth provider. Depending on the OAuth
    provider, the secret is confidential or not. For example, GitHub warns
    that the client secret should be kept secret and not even be checked
    in. They recommend to use a device flow if the client
    secret can't be kept confidential). Google, on the other hand,
    explicitly states that the client secret is not really a secret
    when the authentication is for an installed application.

  The $logger parameter is used for the http server that is started to listen
    for the redirect.

  The $endpoint parameter is the URL where the OAuth provider is located.
    It is provided by the OAuth provider. For example, Google publishes
    the endpoint URL in their
    [discover document](https://accounts.google.com/.well-known/openid-configuration),
    under 'authorization_endpoint'.

  The $token-url parameter is the URL where the OAuth provider can be
    queried for an access token. It is provided by the OAuth provider.
    For example, Google publishes the token URL in their
    [discover document](https://accounts.google.com/.well-known/openid-configuration),
    under 'token_endpoint'.

  If the OAuth provider is accessed through "https", then the $root-certificates
    parameter must contain the root certificates needed to access the OAuth
    provider. If the OAuth provider is accessed through "http", then the
    $root-certificates parameter can be empty.

  The $scopes list identify the resources that the application wants to
    access. For example, Google has URLs like
    "https://www.googleapis.com/auth/userinfo.email" or "https://www.googleapis.com/auth/drive".
    GitHub has "repo", "repo:status", "user", "read:user", "gist", etc.

  The $query-parameters parameter is a map of additional query parameters that
    are passed to the redirect URL. For example, Google allows to pass a
    "login_hint" parameter to the redirect URL to pre-fill the email address
    of the user.

  The $local-storage parameter is used to store the token, so it can be
    reused after the application is restarted.
  */
  constructor.localhost
      --localhost/string="localhost"
      --redirect-path/string
      --client-id/string
      --client-secret/string?
      --logger/log.Logger=(log.default.with-level log.FATAL-LEVEL)
      --endpoint/string
      --token-url/string
      --root-certificates/List
      --scopes/List
      --query-parameters/Map={:}
      --local-storage/LocalStorage:
    if localhost != "localhost" and localhost != "127.0.0.1":
      throw "localhost must be 'localhost' or '127.0.0.1'"

    return LocalhostCodeOAuth_
        --localhost=localhost
        --redirect-path=redirect-path
        --logger=logger
        --endpoint=endpoint
        --client-id=client-id
        --client-secret=client-secret
        --scopes=scopes
        --token-url=token-url
        --root-certificates=root-certificates
        --query-parameters=query-parameters
        --local-storage=local-storage

  /**
  Constructs an OAuth provider that uses a device flow.

  When doing the authentication ($ensure-authenticated), this instance will
    start a device flow.

  The device flow is typically used for embedded devices that don't have
    a browser. Users open the authorization URI in a browser
    on a different device, and then enter the code that is displayed on
    the embedded device. The device flow is also known as "device
    authorization grant".

  The $client-id identifies the application. It is generated by the OAuth
    provider, and used to verify that the redirect_uri is registered for
    the client_id.

  The $endpoint-url and $token-url URIs are provided by the OAuth provider.
    For example, Google publishes the endpoint URL in their
    [discover document](https://accounts.google.com/.well-known/openid-configuration),
    under 'device_authorization_endpoint' and 'token_endpoint'.

  The $scopes identify the resources that the application wants to
    access. For example, Google has
    "https://www.googleapis.com/auth/userinfo.email" or
    "https://www.googleapis.com/auth/drive". GitHub has
    "repo", "repo:status", "user", "gist", etc.
  */
  constructor.device
      --client-id/string
      --endpoint-url/string
      --token-url/string
      --root-certificates/List
      --scopes/List
      --local-storage/LocalStorage:
    return DeviceOAuth_
        --client-id=client-id
        --endpoint-url=endpoint-url
        --token-url=token-url
        --root-certificates=root-certificates
        --scopes=scopes
        --local-storage=local-storage

  refresh --network/net.Client?=null token/Token -> Token:
    if not token.refresh-token:
      throw "No refresh token available."
    with-http-client network --root-certificates=root-certificates_: | client/http.Client |
      response := client.post-json --uri=token-url_ {
        "client_id": client-id_,
        // When using the device flow, some providers don't want the client to have
        // a client secret. However, in those cases we tend to not have a refresh
        // token either. So if the client secret is null we shouldn't reach this line.
        // If there is a provider that has a refresh token and no client secret, we
        // just send null here.
        "client_secret": client-secret_,
        "refresh_token": token.refresh-token,
        "grant_type": "refresh_token",
      }
      new-token := parse-token-response_ response
      if not new-token.refresh-token:
        // Some providers (e.g. Google) only issue a refresh token on the very
        // first exchange and omit it from subsequent refresh responses. Carry
        // the previous one forward so future refreshes still work.
        json := new-token.to-json
        json["refresh_token"] = token.refresh-token
        new-token = Token.from-json json
      return new-token
    unreachable

  abstract do-authentication_ --network/net.Client?=null [block] -> Token

/**
An OAuth authorization code flow.

This flow is used by applications that can open a browser window to
  authenticate the user. The application then receives an authorization code
  that can be exchanged for an access token.

Steps:
- The code flow provides a URL that the user can open in a browser.
- The user authenticates and authorizes the application.
- The user is redirected to a URL that the application has specified.
- The application extracts the authorization code from the URL.
- The application exchanges the authorization code for an access token.

Depending on the OAuth provider this flow is recommended for installed applications
  or not. For example, Google recommends to use this flow for installed applications.
  GitHub recommends to use the device flow for installed applications instead.
*/
class OAuthCodeFlow:
  /**
  The client ID.

  The ID is provided by the OAuth provider and identifies the application.
  */
  client-id/string

  /**
  The client secret.

  The secret is generated by the OAuth provider. Depending on the OAuth
    provider, the secret is confidential or not. For example, GitHub warns
    that the client secret should be kept secret and not even be checked
    in. They recommend to use a device flow if the client
    secret can't be kept confidential). Google, on the other hand,
    explicitly states that the client secret is not really a secret
    when the authentication is for an installed application.
  */
  client-secret/string

  /**
  The base URI of the authorization endpoint.

  It is provided by the OAuth provider. For example, Google publishes
    the endpoint URL in their
    [discover document](https://accounts.google.com/.well-known/openid-configuration),
    under 'authorization_endpoint'.
  */
  endpoint/string

  /**
  The URL where the user is redirected after logging in.

  The authentication provider requires the redirect URL to be registered
    beforehand. The user of this flow must have a server that listens on
    this URL. The server must call $get-token with the parameters provided
    in the redirect.
  */
  redirect-url/string

  /**
  The URL where the library can obtain the token.
  */
  token-url/string

  /**
  The root certificates needed to access $token-url.
  */
  root-certificates/List

  /**
  Additional query parameters that are passed to the redirect URL.
  */
  query-parameters/Map

  constructor
      --.endpoint
      --.client-id
      --.client-secret
      --.token-url
      --.redirect-url
      --.root-certificates
      --.query-parameters={:}:

  /**
  Returns the URL where the user can log in.

  The $scopes list identify the resources that the application wants to
    access. For example, Google has URLs like
    "https://www.googleapis.com/auth/userinfo.email" or "https://www.googleapis.com/auth/drive".
    GitHub has "repo", "repo:status", "user", "read:user", "gist", etc.

  If provided, then the $state is passed to the redirect URL. It is an arbitrary
    string and typically used to prevent CSRF attacks. On GitHub it is supposed to
    be an unguessable random string, to protect against cross-site request forgery
    attacks. Google suggest additional uses, such as directing the user to the correct
    resource, sending nonces, etc. The $state is always sent verbatim to
    the $redirect-url. Note that this instance does *not* verify that the returned
    state matches the provided state. The caller of $get-token must do that.
  */
  get-url --scopes/List state/string?=null -> string:
    parameters := query-parameters.copy
    parameters["client_id"] = client-id
    parameters["redirect_uri"] = redirect-url
    parameters["scope"] = scopes.join " "
    parameters["response_type"] = "code"
    if state: parameters["state"] = state

    return "$endpoint?$(build-url-encoded-query-parameters parameters)"

  /**
  Returns an authorization token.

  The $response-url is the URL (including the query parameters) that the server
    received in the redirect URL.

  The $network is used to obtain the token. If $network is null, then a new
    network is created and closed after the token is obtained.
  */
  get-token response-url/string --network/net.Client?=null -> Token:
    parsed := url.QueryString.parse response-url

    code := parsed.parameters.get "code"
    if not code:
      exception := AuthException
          --error-code="missing_code"
          --error-description="The code is missing"
      throw exception

    with-http-client network --root-certificates=root-certificates: | client/http.Client |
      parameters := {
        "code": code,
        "client_id": client-id,
        "client_secret": client-secret,
        "redirect_uri": redirect-url,
        "grant_type": "authorization_code",
      }
      encoded-params := build-url-encoded-query-parameters parameters
      headers := http.Headers
      headers.add "Accept" "application/json"
      url-with-code := "$token-url?$encoded-params"
      response := client.get --uri=url-with-code --headers=headers
      return parse-token-response_ response

    unreachable

/**
Opens the default browser with the given URL.

Only works on Linux, macOS and Windows.
If launching the browser fails, no error is reported.
*/
open-browser url/string -> none:
  platform := system.platform
  catch:
    command/string? := null
    args/List? := null
    if platform == system.PLATFORM-LINUX:
      command = "xdg-open"
      args = [ url ]
    else if platform == system.PLATFORM-MACOS:
      command = "open"
      args = [ url ]
    else if platform == system.PLATFORM-WINDOWS:
      command = "cmd"
      escaped-url := url.replace "&" "^&"
      args = [ "/c", "start", escaped-url ]
    // If we have a supported platform try to open the URL.
    // For all other platforms don't do anything.
    if command != null:
      fork-data := pipe.fork
          true  // Use path.
          pipe.PIPE-CREATED  // Stdin.
          pipe.PIPE-CREATED  // Stdout.
          pipe.PIPE-CREATED  // Stderr.
          command
          [ command ] + args
      pid := fork-data[3]
      task --background::
        // The 'open' command should finish in almost no time.
        // If it takes more than 20 seconds, kill it.
        exception := catch: with-timeout --ms=20_000:
          pipe.wait-for pid
        if exception == DEADLINE-EXCEEDED-ERROR:
          SIGKILL ::= 9
          catch: pipe.kill_ pid SIGKILL
