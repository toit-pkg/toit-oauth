// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import encoding.json
import host.file
import oauth

/**
Example: a simple file-backed $oauth.LocalStorage implementation.

The library persists tokens through whatever $oauth.LocalStorage you pass in.
  This example shows a minimal implementation that writes a JSON file to
  disk so the user does not have to log in again on the next run.

For real applications consider using a path under the user's config
  directory, restricting permissions on the file, or storing the token in
  the OS keychain.
*/

class FileLocalStorage implements oauth.LocalStorage:
  path_/string

  constructor .path_:

  has-auth -> bool:
    return file.is-file path_

  get-auth -> any?:
    if not has-auth: return null
    return json.decode (file.read-contents path_)

  set-auth value/any -> none:
    stream := file.Stream.for-write path_
    try:
      stream.out.write (json.encode value)
    finally:
      stream.close

  remove-auth -> none:
    if file.is-file path_: file.delete path_

main:
  storage := FileLocalStorage "/tmp/oauth-token.json"

  client := oauth.OAuth.device
      --client-id="<your-client-id>"
      --endpoint-url="https://oauth2.googleapis.com/device/code"
      --token-url="https://oauth2.googleapis.com/token"
      --root-certificates=[]  // Replace with real roots, e.g. certificate-roots.ALL.
      --scopes=["https://www.googleapis.com/auth/userinfo.email"]
      --local-storage=storage

  client.ensure-authenticated: | url code |
    print "Open $url and enter $code"

  print "Token persisted at /tmp/oauth-token.json"
