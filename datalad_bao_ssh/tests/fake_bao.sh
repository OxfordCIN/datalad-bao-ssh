#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="${BAO_FAKE_HOME:-${XDG_STATE_HOME:-$HOME/.local/state}/bao-fake}"
TOKEN_FILE="$STATE_DIR/token"
CA_KEY="$STATE_DIR/ssh_ca"
CA_PUB="$STATE_DIR/ssh_ca.pub"

mkdir -p "$STATE_DIR"

die() {
  echo "bao: $*" >&2
  exit 1
}

rand_token() {
  if command -v openssl >/dev/null 2>&1; then
    printf 'fake-%s' "$(openssl rand -hex 16)"
  else
    printf 'fake-%s' "$(date +%s%N)"
  fi
}

ensure_base_token() {
  if [[ -n "${BAO_FAKE_TOKEN:-}" ]]; then
    printf '%s' "$BAO_FAKE_TOKEN"
    return
  fi

  if [[ -f "$TOKEN_FILE" ]]; then
    cat "$TOKEN_FILE"
    return
  fi

  local token
  token="$(rand_token)"
  printf '%s' "$token" >"$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE" 2>/dev/null || true
  printf '%s' "$token"
}

ensure_ca() {
  if [[ -f "$CA_KEY" && -f "$CA_PUB" ]]; then
    return
  fi

  ssh-keygen -q -t ed25519 -N '' -f "$CA_KEY" >/dev/null
}

read_public_key_arg() {
  local spec="$1"
  if [[ "$spec" == @* ]]; then
    cat "${spec#@}"
  elif [[ -f "$spec" ]]; then
    cat "$spec"
  else
    printf '%s\n' "$spec"
  fi
}

sign_public_key() {
  local role="${1:-default}"
  local pubkey_spec="${2:-}"
  local principals="${3:-test}"
  local ttl="${4:-1h}"

  [[ -n "$pubkey_spec" ]] || die "missing public key"

  ensure_ca

  local tmpdir pubfile certfile identity
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  pubfile="$tmpdir/key.pub"
  certfile="$tmpdir/key-cert.pub"
  identity="fake-${role}"

  read_public_key_arg "$pubkey_spec" >"$pubfile"
  ssh-keygen -q -s "$CA_KEY" -I "$identity" -n "$principals" -V "-5m:+$ttl" "$pubfile" >/dev/null

  [[ -f "$certfile" ]] || die "ssh certificate was not created"
  cat "$certfile"
}

prompt_password() {
  local password=""
  if [[ -t 0 ]]; then
    printf 'Password (will not be echoed): ' >&2
    read -r -s password
    printf '\n' >&2
  else
    if [[ -n "${BAO_FAKE_LDAP_PASSWORD:-}" ]]; then
      password="$BAO_FAKE_LDAP_PASSWORD"
    else
      die "LDAP login requires an interactive terminal or BAO_FAKE_LDAP_PASSWORD"
    fi
  fi

  printf '%s' "$password"
}

fake_login_token() {
  local method="${1:-token}"
  local principal="${2:-}"
  local extra="${3:-}"

  if [[ -n "${BAO_FAKE_TOKEN:-}" ]]; then
    printf '%s' "$BAO_FAKE_TOKEN"
    return
  fi

  local base
  base="$(ensure_base_token)"

  case "$method" in
    oidc)
      if [[ -n "$principal" ]]; then
        printf '%s-oidc-%s' "$base" "$principal"
      else
        printf '%s-oidc' "$base"
      fi
      ;;
    ldap)
      if [[ -n "$principal" ]]; then
        printf '%s-ldap-%s' "$base" "$principal"
      else
        printf '%s-ldap' "$base"
      fi
      ;;
    *)
      printf '%s' "$base"
      ;;
  esac
}

cmd="${1:-}"
shift || true

case "$cmd" in
  login)
    method="token"
    format="text"
    token_only=false
    username=""
    role=""
    path=""
    password=""

    while [[ $# -gt 0 ]]; do
      case "$1" in
        -method=*)
          method="${1#-method=}"
          shift
          ;;
        -format=json)
          format="json"
          shift
          ;;
        -token-only)
          token_only=true
          shift
          ;;
        username=*)
          username="${1#username=}"
          shift
          ;;
        -username=*)
          username="${1#-username=}"
          shift
          ;;
        role=*)
          role="${1#role=}"
          shift
          ;;
        -role=*)
          role="${1#-role=}"
          shift
          ;;
        path=*)
          path="${1#path=}"
          shift
          ;;
        -path=*)
          path="${1#-path=}"
          shift
          ;;
        password=*)
          password="${1#password=}"
          shift
          ;;
        -password=*)
          password="${1#-password=}"
          shift
          ;;
        -method)
          method="${2:-token}"
          shift 2
          ;;
        -username)
          username="${2:-}"
          shift 2
          ;;
        -role)
          role="${2:-}"
          shift 2
          ;;
        -path)
          path="${2:-}"
          shift 2
          ;;
        -password)
          password="${2:-}"
          shift 2
          ;;
        -*)
          shift
          ;;
        *)
          if [[ -z "$username" && "$method" == "ldap" ]]; then
            username="$1"
          fi
          shift
          ;;
      esac
    done

    case "$method" in
      token|"")
        token="$(ensure_base_token)"
        ;;

      oidc)
        # Fake OIDC: accept the request and return a token.
        # Optional role/path are accepted but not enforced.
        token="$(fake_login_token oidc "${role:-$username}" "${path:-}")"
        ;;

      ldap)
        # Fake LDAP: require username and prompt for password.
        [[ -n "$username" ]] || die "ldap login requires username=... or -username ..."
        if [[ -z "$password" ]]; then
          password="$(prompt_password)"
        fi

        # Very light fake validation: accept any non-empty password.
        [[ -n "$password" ]] || die "empty password rejected"

        token="$(fake_login_token ldap "$username" "$path")"
        ;;

      *)
        # Unknown methods still succeed as a stub unless you prefer strictness.
        token="$(fake_login_token "$method" "$username" "$path")"
        ;;
    esac

    printf '%s\n' "$token" >"$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE" 2>/dev/null || true

    if [[ "$format" == "json" ]]; then
      cat <<EOF
{"auth":{"client_token":"$token","metadata":{"method":"$method","username":"$username","role":"$role","path":"$path"}}}
EOF
    else
      if $token_only; then
        printf '%s\n' "$token"
      else
        printf 'Success! You are now authenticated.\n'
        printf '%s\n' "$token"
      fi
    fi
    ;;

  write)
    field="signed_key"
    endpoint=""
    pubkey_spec=""
    principals="${BAO_FAKE_PRINCIPALS:-test}"
    ttl="${BAO_FAKE_TTL:-1h}"

    while [[ $# -gt 0 ]]; do
      case "$1" in
        -field=*)
          field="${1#-field=}"
          shift
          ;;
        ssh/sign/*)
          endpoint="$1"
          shift
          ;;
        public_key=*)
          pubkey_spec="${1#public_key=}"
          shift
          ;;
        valid_principals=*)
          principals="${1#valid_principals=}"
          shift
          ;;
        ttl=*)
          ttl="${1#ttl=}"
          shift
          ;;
        *)
          shift
          ;;
      esac
    done

    [[ "$endpoint" == ssh/sign/* ]] || die "expected endpoint like ssh/sign/<role>"
    role="${endpoint#ssh/sign/}"
    sign_public_key "$role" "$pubkey_spec" "$principals" "$ttl"
    ;;

  ssh)
    sub="${1:-}"
    shift || true
    case "$sub" in
      sign)
        role="default"
        pubkey_spec=""
        principals="${BAO_FAKE_PRINCIPALS:-test}"
        ttl="${BAO_FAKE_TTL:-1h}"

        while [[ $# -gt 0 ]]; do
          case "$1" in
            -role)
              role="${2:-default}"
              shift 2
              ;;
            -public-key)
              pubkey_spec="${2:-}"
              shift 2
              ;;
            -principals)
              principals="${2:-}"
              shift 2
              ;;
            -ttl)
              ttl="${2:-1h}"
              shift 2
              ;;
            *)
              shift
              ;;
          esac
        done

        sign_public_key "$role" "$pubkey_spec" "$principals" "$ttl"
        ;;

      *)
        die "unsupported ssh subcommand: $sub"
        ;;
    esac
    ;;

  *)
    cat >&2 <<EOF
Usage:
  bao login [-method=token|oidc|ldap] [username=alice] [role=dev] [-format=json] [-token-only]
  bao write -field=signed_key ssh/sign/<role> public_key=@/path/to/key.pub valid_principals=user ttl=1h
  bao ssh sign -role <role> -public-key /path/to/key.pub -principals user -ttl 1h

Environment:
  BAO_FAKE_TOKEN          fixed token to return
  BAO_FAKE_HOME           state directory
  BAO_FAKE_LDAP_PASSWORD  password used when stdin is not a tty
  BAO_FAKE_PRINCIPALS     default SSH principals
  BAO_FAKE_TTL            default SSH cert TTL
EOF
    exit 1
    ;;
esac
