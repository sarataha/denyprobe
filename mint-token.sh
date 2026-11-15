#!/usr/bin/env bash
# Print a GitHub App installation token. Needs APP_ID, INSTALLATION_ID, APP_KEY (path to .pem).
set -euo pipefail
b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now=$(date +%s)
header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64)
payload=$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' $((now-60)) $((now+540)) "$APP_ID" | b64)
sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$APP_KEY" | b64)
curl -sf -X POST \
  -H "Authorization: Bearer $header.$payload.$sig" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/app/installations/$INSTALLATION_ID/access_tokens" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])'
