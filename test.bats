#!/usr/bin/env bats

vault="vault"

# Debugging output for the tests themselves
logfile="test.log"

log() {
  printf "%s - $1\n" "$(date)" >> ${logfile}
}

start_vault() {
  local plugin_dir=$1

  log "Starting Vault"

  if [[ "${plugin_dir}" == "" ]]; then
    ${vault} server -dev > /dev/null 2> /dev/null &
  else
    ${vault} server -dev -dev-plugin-dir="${plugin_dir}" > /dev/null 2> /dev/null &
  fi

  # Wait for Vault to become available
  echo "$(date) - Waiting for vault to become available..." >> ${logfile}
  run ${vault} status -address=${VAULT_ADDR};
  while [ "$status" -ne 0 ]; do
    sleep 1
    run ${vault} status -address=${VAULT_ADDR}
  done
  sleep 1
}

stop_vault() {
  log "Stopping vault..."
  pkill vault
  log "Vault has stopped"
}

setup() {
  start_vault "/Users/mgolowka/dev/vault/plugins/"

  vault secrets enable -path=jwt vault-plugin-secrets-jwt
}

teardown() {
  stop_vault
}

run_lifecycle() {
  name=$1
  shift

  log "Testing ${name} $*..."
  vault write jwt/roles/${name}/config exp="1s" "$@"
  vault read jwt/roles/${name}/config

  # Generate a token and ensure that it isn't empty
  run vault read -format json jwt/roles/${name}/generate
  log "${output}"
  [ ${status} -eq 0 ]
  TOKEN=$(echo "${output}" | jq -r .data.token)
  [ "${TOKEN}" != "" ]

  # Validate the JWT before expiration
  vault write jwt/roles/${name}/validate token="${TOKEN}"

  sleep 2 # Wait for JWT to expire
  run vault write -format json jwt/roles/${name}/validate token="${TOKEN}"
  log "${output}"
  [ ${status} -ne 0 ]

  vault delete jwt/roles/${name}/config
}

@test "RS256 - Generated key" {
  run_lifecycle "RS256" alg=RS256 foo=bar
}

@test "RS384 - Generated key" {
  run_lifecycle "RS384" alg=RS384 foo=bar
}

@test "RS512 - Generated key" {
  run_lifecycle "RS512" alg=RS512 foo=bar
}

@test "RS256 - Provided key" {
  run_lifecycle "RS256" alg=RS256 foo=bar key="@$(pwd)/testdata/rsa_private.key"
}

@test "RS384 - Provided key" {
  run_lifecycle "RS384" alg=RS384 foo=bar key="@$(pwd)/testdata/rsa_private.key"
}

@test "RS512 - Provided key" {
  run_lifecycle "RS512" alg=RS512 foo=bar key="@$(pwd)/testdata/rsa_private.key"
}

@test "ES256 - Generated key" {
  run_lifecycle "ES256" alg=ES256 foo=bar
}

@test "ES384 - Generated key" {
  run_lifecycle "ES384" alg=ES384 foo=bar
}

@test "ES512 - Generated key" {
  run_lifecycle "ES512" alg=ES512 foo=bar
}

@test "ES256 - Provided key" {
  run_lifecycle "ES256" alg=ES256 foo=bar key="@$(pwd)/testdata/es256_private.key"
}

@test "ES384 - Provided key" {
  run_lifecycle "ES384" alg=ES384 foo=bar key="@$(pwd)/testdata/es384_private.key"
}

@test "ES512 - Provided key" {
  run_lifecycle "ES512" alg=ES512 foo=bar key="@$(pwd)/testdata/es512_private.key"
}

@test "HS256 - Generated key" {
  run_lifecycle "HS256" alg=HS256 foo=bar
}

@test "HS384 - Generated key" {
  run_lifecycle "HS384" alg=HS384 foo=bar
}

@test "HS512 - Generated key" {
  run_lifecycle "HS512" alg=HS512 foo=bar
}

@test "HS256 - Provided key" {
  key=$(echo -n "foobar" | openssl dgst -sha256)
  run_lifecycle "HS256" alg=HS256 foo=bar key="${key}"
}

@test "HS384 - Provided key" {
  key=$(echo -n "foobar" | openssl dgst -sha384)
  run_lifecycle "HS384" alg=HS384 foo=bar key="${key}"
}

@test "HS512 - Provided key" {
  key=$(echo -n "foobar" | openssl dgst -sha512)
  run_lifecycle "HS512" alg=HS512 foo=bar key="${key}"
}
