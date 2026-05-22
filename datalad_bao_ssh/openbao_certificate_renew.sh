#!/bin/bash
set -euo pipefail

DEBUG="${DATALAD_BAO_SSH_DEBUG:-0}"
CACERT="${DATALAD_BAO_SSH_CA_CERT:-}"
ROLE="**ROLE**"
PRINCIPAL="**PRINCIPAL**"
CERTTYPE="**CERTTYPE**"
BAOHOST="**BAOHOST**"
BAOPORT="**BAOPORT**"
BAOAUTH="**BAOAUTH**"
BAOOPENID="**BAOOPENID**"
BAOBIN="**BAOBIN**"
BAOUSERNAME="**USERNAME**"

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

urlencode() {
    local s="$1"
    local out=""
    local i c hex
    for (( i=0; i<${#s}; i++ )); do
        c="${s:$i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-])
                out+="$c"
                ;;
            *)
                printf -v hex '%%%02X' "'$c"
                out+="$hex"
                ;;
        esac
    done
    printf '%s\n' "$out"
}

remove_token() {
  rm -f "${HOME}/.bao-token"
}

remove_tmpdir() {
  remove_token
  if [ -n "$tmpdir" ]; then
    rm -rf "${tmpdir}"
  fi
}

certificate_expiry() {
  ssh-keygen -L -f "$CERT" \
    | awk '/Valid:/ {print $5}'
}

if [ -f "$CERT" ]; then
  debug "Found $CERT"
  expiry=$(certificate_expiry)
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

# Look for bao command
if command -v bao >/dev/null 2>&1 || command -v "$BAOBIN" 2>&1; then
  VAULT_ADDR="$BAOSRV"
  export VAULT_ADDR
  if [ -n "$CACERT" ]; then
    VAULT_CACERT="$CACERT"
    export VAULT_CACERT
  fi
  username="$BAOUSERNAME"
else
  if ! command -v jq >/dev/null 2>&1; then
    error "jq command not found - this is necessary if 'bao' isn't installed"
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    error "curl command not found - this is necessary if 'bao' isn't installed"
    exit 1
  fi
  BAOBIN=""
  if [ "$BAOOPENID" = "1" ]; then
    error "Can't find the 'bao' client necessary for logins" >&2
    exit 1
  fi
  username=$(urlencode "$BAOUSERNAME")
  printf "Passphrase: "
  read -r -s PASSWORD
  echo ""
fi

if [ ! -d "$HOME/.ssh" ]; then
  mkdir "$HOME/.ssh"
  chmod 0700 "$HOME/.ssh"
fi

if [ ! -w "$HOME/.ssh" ]; then
  error "Unable to write to $HOME/.ssh"
  exit 1
fi

# Attempt Bao login
info "Logging into access control server..."
if [ -n "$CACERT" ]; then
  ca_opt=(--cacert "$CACERT")
else
  ca_opt=()
fi

if [ -n "$BAOBIN" ]; then
  debug "Logging in with bao with method ${BAOAUTH}"
  if [ "$BAOOPENID" = "0" ]; then
    "$BAOBIN" login -method="${BAOAUTH}" username="$username"
  else
    "$BAOBIN" login -method="${BAOAUTH}" role="${ROLE}"
  fi
  trap remove_token EXIT INT TERM
else
  debug "Logging in with cURL with method ${BAOAUTH}"
  TOKEN=$(
    printf '%s' "$PASSWORD" |
    jq -R '{password:.}' |
    curl -s "${ca_opt[@]}" \
      --request PUT \
      --header "X-Vault-Request: true" \
      --data-binary @- \
      "${BAOSRV}/v1/auth/${BAOAUTH}/login/${username}" | jq -r '.auth.client_token')
  unset PASSWORD
  if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    error "Login failed"
    exit 1
  fi
fi
tmpdir=$(mktemp -d)
trap remove_tmpdir EXIT INT TERM
dl_key_f="${tmpdir}/${KEYFILE}"
dl_pub_f="${tmpdir}/${PUBFILE}"
dl_cert_f="${tmpdir}/${CERTFILE}"

debug "Generating key pair"
ssh-keygen -t ed25519 -C "${username}@${BAOHOST}" \
    -f "$dl_key_f" -N "" -q

if [ -n "$BAOBIN" ]; then
  debug "Signing certificate with bao against $ROLE"
  SIGNED_CERT=$(
    "$BAOBIN" write -field=signed_key "ssh-client-signer/sign/$ROLE" \
      public_key="@$dl_pub_f" \
      valid_principals="${PRINCIPAL},${username}"
  )
else
  debug "Signing certificate with cURL against $ROLE"
  SIGNED_CERT=$(
    jq -n \
      --rawfile public_key "$dl_pub_f" \
      --arg valid_principals "${PRINCIPAL},${username}" \
      '{public_key:$public_key, valid_principals:$valid_principals}' |
    curl -s "${ca_opt[@]}" \
      --config <(
      printf 'header = "X-Vault-Token: %s"\n' "$TOKEN"
      printf 'header = "X-Vault-Request: true"\n'
      printf 'url = "%s"\n' "$BAOSRV/v1/ssh-client-signer/sign/$ROLE"
      printf 'request = "PUT"\n'
    ) \
    --data-binary @- | \
    jq -r '.data.signed_key')
fi

if [ "$SIGNED_CERT" = "null" ] || [ -z "$SIGNED_CERT" ]; then
  error "Failed to setup SSH logins"
  exit 1
fi

echo "$SIGNED_CERT" > "$dl_cert_f"
chmod 0644 "${dl_cert_f}"

mv "$dl_key_f" "${KEY}" && \
  mv "$dl_cert_f" "${CERT}" && \
  mv "$dl_pub_f" "${PUB}"
remove_tmpdir

info "SSH logins enabled until $(certificate_expiry)"
