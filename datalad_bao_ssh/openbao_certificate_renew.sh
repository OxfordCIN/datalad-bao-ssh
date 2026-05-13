#!/bin/bash
set -uo pipefail

DEBUG="${DATALAD_BAO_SSH_DEBUG:-0}"
CACERT="${DATALAD_BAO_SSH_CA_CERT:-}"
ROLE="${DATALAD_BAO_SSH_ROLE:-**ROLE**}"
PRINCIPAL="${DATALAD_BAO_SSH_PRINCIPAL:-**PRINCIPAL**}"
CERTTYPE="${DATALAD_BAO_SSH_CERTTYPE:-**CERTTYPE**}"
BAOHOST="${DATALAD_BAO_SSH_BAOHOST:-**BAOHOST**}"
BAOPORT="${DATALAD_BAO_SSH_BAOPORT:-**BAOPORT**}"
BAOAUTH="${DATALAD_BAO_SSH_BAOAUTH:-**BAOAUTH**}"

BAOSRV="https://${BAOHOST}:${BAOPORT}"
KEYFILE="id-${CERTTYPE}-${BAOHOST//./-}"
PUBFILE="${KEYFILE}.pub"
CERTFILE="${KEYFILE}-cert.pub"
KEY="${HOME}/.ssh/${KEYFILE}"
PUB="${HOME}/.ssh/${PUBFILE}"
CERT="${HOME}/.ssh/${CERTFILE}"

log() {
    printf '[%s] %s\n' "$1" "$2" >&2
}

debug() {
    [[ "$DEBUG" == "1" ]] && log DEBUG "$*"
}

info() {
    log INFO "$*"
}

warn() {
    log WARN "$*"
}

error() {
    log ERROR "$*"
}

if [ -f "$CERT" ]; then
  debug "Found $CERT"
  expiry=$(ssh-keygen -L -f "$CERT" \
    | awk '/Valid:/ {print $5}')
  if ! epoc=$(date -d "$expiry" +%s 2>/dev/null); then
    epoc=$(date -j -f "%Y-%m-%dT%H:%M:%S" "$expiry" +%s)
  fi
  now=$(date +%s)
  debug "Expiry: $expiry, Epoc: $epoc, Now: $now"
  if [ "$epoc" -gt $((now + 300)) ]; then
    debug "Certificate not expired, exiting"
    exit 0
  fi
fi

if [ ! -d "$HOME/.ssh" ]; then
  mkdir "$HOME/.ssh"
  chmod 0700 "$HOME/.ssh"
  if which restorecon >/dev/null 2>&1 ; then
    restorecon -R "$HOME/.ssh"
  fi
fi

printf "Username: "
read -r username
printf "Passphrase: "
read -r -s PASSWORD
echo ""

# Attempt Bao login
echo "Logging into access control server..."
if [ -n "$CACERT" ]; then
  ca_opt=(--cacert "$CACERT")
else
  ca_opt=()
fi
debug "$DEBUG"
debug "$CACERT"
debug "$ROLE"
debug "$PRINCIPAL"
debug "$CERTTYPE"
debug "$BAOHOST"
debug "$BAOPORT"
debug "$BAOAUTH"
debug "${BAOSRV}/v1/auth/${BAOAUTH}/login/${username}"
TOKEN=$(
  printf '%s' "$PASSWORD" |
  jq -R '{password:.}' |
  curl -s "${ca_opt[@]}" \
    --request POST \
    --header "Content-Type: application/json" \
    --data-binary @- \
    "${BAOSRV}/v1/auth/${BAOAUTH}/login/${username}" | jq -r '.auth.client_token')

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
  echo "Login failed" >&2
  exit 1
fi

unset PASSWORD
echo "Creating access token..."
tmpdir=$(mktemp -d)
dl_key_f="${tmpdir}/${KEYFILE}"
dl_pub_f="${tmpdir}/${PUBFILE}"
dl_cert_f="${tmpdir}/${CERTFILE}"

ssh-keygen -t ed25519 -C "${username}@${BAOHOST}" \
    -f "$dl_key_f" -N "" -q

SIGNED_CERT=$(
  jq -n \
    --rawfile public_key "$dl_pub_f" \
    --arg valid_principals "${PRINCIPAL},${username}" \
    '{public_key:$public_key, valid_principals:$valid_principals}' |
  curl -s "${ca_opt[@]}" \
    --config <(
    printf 'header = "X-Vault-Token: %s"\n' "$TOKEN"
    printf 'url = "%s"\n' "$BAOSRV/v1/ssh-client-signer/sign/$ROLE"
    printf 'request = "POST"\n'
  ) \
  --data-binary @- | \
  jq -r '.data.signed_key')

if [ "$SIGNED_CERT" = "null" ] || [ -z "$SIGNED_CERT" ]; then
  echo "Failed" >&2
  exit 1
fi

echo "$SIGNED_CERT" > "$dl_cert_f"
chmod 0644 "${dl_cert_f}"

mv "$dl_key_f" "${KEY}" && \
  mv "$dl_cert_f" "${CERT}" && \
  mv "$dl_pub_f" "${PUB}"
rmdir "$tmpdir"
