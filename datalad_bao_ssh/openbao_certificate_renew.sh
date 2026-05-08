#!/bin/bash
set -euo pipefail

DEBUG="${DATALAD_BAO_SSH_DEBUG:-0}"
CACERT="${DATALAD_BAO_SSH_CA_CERT:-}"
ROLE="${DATALAD_BAO_SSH_ROLE:-**ROLE**}"
PRINCIPAL="${DATALAD_BAO_SSH_PRINCIPAL:-**PRINCIPAL**}"
CERTTYPE="${DATALAD_BAO_SSH_CERT_TYPE:-**CERTTYPE**}"
BAOHOST="${DATALAD_BAO_SSH_BAOHOST:-**BAOHOST**}"
BAOPORT="${DATALAD_BAO_SSH_BAOPORT}:-**BAOPORT**}"
BAOAUTH="${DATALAD_BAO_SSH_AUTHSERVICE}:**BAOAUTH**}"

BAOSRV="https://${BAOHOST}:${BAOPORT}"
KEYFILE="id-${CERTTYPE}-${BAOHOST//./-}"
PUBFILE="${KEYFILE}.pub"
CERTFILE="${KEYFILE}-cert.pub"

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

if [ -f "$CERTFILE" ]; then
  expiry=$(ssh-keygen -L -f "$CERTFILE" \
    | awk '/Valid:/ {print $5}')
  if ! epoc=$(date -d "$expiry" +%s 2>/dev/null); then
    epoc=$(date -j -f "%Y-%m-%dT%H:%M:%S" "$expiry" +%s)
  fi

  now=$(date +%s)
  if [ "$epoc" -gt $((now + 300)) ]; then
    debug "Certificate not expired, exiting"
    exit 0
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
TOKEN=$(curl -s "${ca_opt[@]}" \
    --request POST \
    --header "Content-Type: application\json" \
    --data "{\"password\":\"$PASSWORD\"}" \
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

SIGNED_CERT=$(curl -s "${ca_opt[@]}" \
  --header "X-Vault-Token: $TOKEN" \
  --request POST \
  --data "{\"public_key\":\"$(cat "${dl_pub_f}")\", \"valid_principals\":\"${PRINCIPAL},${username}\"}" \
  "$BAOSRV/v1/ssh-client-signer/sign/$ROLE" | jq -r '.data.signed_key')

if [ "$SIGNED_CERT" = "null" ] || [ -z "$SIGNED_CERT" ]; then
  echo "Failed" >&2
  exit 1
fi

echo "$SIGNED_CERT" > "$dl_cert_f"
chmod 0644 "${dl_cert_f}"

mv "$dl_key_f" "${HOME}/.ssh/${KEYFILE}" && \
  mv "$dl_cert_f" "${HOME}/.ssh/${CERTFILE}" && \
  mv "$dl_pub_f" "${HOME}/.ssh/${PUBFILE}"
rmdir "$tmpdir"
