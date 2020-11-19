#!/bin/bash

. demo-magic.sh -w

clear

# Vault should be running outside of this script
pkill vault

while [ true ]; do
	vault status > /dev/null 2> /dev/null
	if [ $? -eq 0 ]; then
		break;
	fi
done

TYPE_SPEED=80

# Enable the engine
pe "vault secrets enable -path=jwt vault-plugin-secrets-jwt"

##################################
##### RSA with generated key #####
echo
echo "##### RSA with generated key #####"
pe "vault write jwt/roles/rsa_role/config alg=RS256 exp=10s foo=bar bar=baz"

p "vault read -format json jwt/roles/rsa_role/config"
vault read -format json jwt/roles/rsa_role/config | jq .
echo # Give visual space

p "vault read -format json jwt/roles/rsa_role/generate"
vault read -format=json jwt/roles/rsa_role/generate | jq .

# Not actually using the token from the previous command, but we're never showing it below so we can fake it
TOKEN=$(vault read -format=json jwt/roles/rsa_role/generate | jq -r .data.token)
echo # Give visual space

echo "$ vault write -format json jwt/roles/rsa_role/validate token=\${TOKEN}"
vault write -format json jwt/roles/rsa_role/validate token=${TOKEN} | jq .
echo # Give visual space

echo -n "Waiting for token to expire..."
while [ true ]; do
	vault write jwt/roles/rsa_role/validate token=${TOKEN} > /dev/null 2> /dev/null
	if [ $? -ne 0 ]; then
		break;
	fi
	sleep 0.5
done
echo "Done"

p "vault write -format json jwt/roles/rsa_role/validate token=\${TOKEN}"
vault write -format json jwt/roles/rsa_role/validate token=${TOKEN} | jq .

BAD_TOKEN="eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiYWQgc3ViamVjdCIsIm5hbWUiOiJFdmlsIEdlbml1cyIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.farZ_6iRaUMxgEnZIawxyfYZu_xI-iqVO4ZcosaD5DwVMD3_yJOUhQRzvqibT2rnPaSwOXAJCdjFrwzpoPgx-TBiVjeDxA31P_sm8zPDb8YOearT9-VlWOGZ0U4H5N36z1f0LJatwjqwEnAe5uZisg5QeUB97cVCk0_3Abflm9zLUj0QBXf99RhNW5OyMpb4pqKdBRSsOgMa7FmPAcGsEzG8y6WFvHjjYBNvTaoJELIJKckuoLqQB4Bxvi8Auc0noUa-fvRh2Gn80gKcoBhJv0kV9HL--3LglhfAI0GOP77BaCDoy3C79iALdpejVbBonPA70zXuag87bwu9UrU5Cw"
p "vault write jwt/roles/rsa_role/validate token=\${BAD_TOKEN}"
vault write jwt/roles/rsa_role/validate token=${BAD_TOKEN}

vault delete jwt/roles/rsa_role/config
wait

#################################
##### RSA with provided key #####
echo
echo "##### RSA with provided key #####"

pe "vault write jwt/roles/rsa_role/config alg=RS256 exp=7s foo=bar bar=baz key=@rsa_private.key"

p "vault read -format json jwt/roles/rsa_role/generate"
vault read -format=json jwt/roles/rsa_role/generate | jq .

# Not actually using the token from the previous command, but we're never showing it below so we can fake it
TOKEN=$(vault read -format=json jwt/roles/rsa_role/generate | jq -r .data.token)
echo # Give visual space

echo "vault write -format json jwt/roles/rsa_role/validate token=\${TOKEN}"
vault write -format json jwt/roles/rsa_role/validate token=${TOKEN} | jq .
echo # Give visual space

echo -n "Waiting for token to expire..."
while [ true ]; do
	vault write jwt/roles/rsa_role/validate token=${TOKEN} > /dev/null 2> /dev/null
	if [ $? -ne 0 ]; then
		break;
	fi
	sleep 0.5
done
echo "Done"

p "vault write -format json jwt/roles/rsa_role/validate token=\${TOKEN}"
vault write -format json jwt/roles/rsa_role/validate token=${TOKEN} | jq .

#################################
##### Nested data with HMAC #####
echo
echo "##### HMAC with generated key & nested claims #####"
p "cat nested_data.json"
cat nested_data.json | jq .

p 'curl -X PUT -H "X-Vault-Request: true" -H "X-Vault-Token: $(vault print token)" -d @nested_data.json ${VAULT_ADDR}/v1/jwt/roles/hmac_role/config'
curl -X PUT -H "X-Vault-Request: true" -H "X-Vault-Token: $(vault print token)" -d @nested_data.json ${VAULT_ADDR}/v1/jwt/roles/hmac_role/config

p "vault read -format json jwt/roles/hmac_role/config"
vault read -format json jwt/roles/hmac_role/config | jq .
echo # Give visual space

p "vault read -format json jwt/roles/hmac_role/generate"
vault read -format json jwt/roles/hmac_role/generate | jq .
echo # Give visual space

TOKEN=$(vault read -format json jwt/roles/hmac_role/generate | jq -r .data.token)

echo "vault write -format json jwt/roles/hmac_role/validate token=\${TOKEN}"
vault write -format json jwt/roles/hmac_role/validate token=${TOKEN} | jq .
echo # Give visual space

echo -n "Waiting for token to expire..."
while [ true ]; do
	vault write jwt/roles/hmac_role/validate token=${TOKEN} > /dev/null 2> /dev/null
	if [ $? -ne 0 ]; then
		break;
	fi
	sleep 0.5
done
echo "Done"

p "vault write -format json jwt/roles/hmac_role/validate token=\${TOKEN}"
vault write -format json jwt/roles/hmac_role/validate token=${TOKEN} | jq .

echo "Features:"
wait
echo "- Key types:"
echo "  - ✅ RSA   (RS256, RS384, RS512)"
echo "  - ✅ HMAC  (HS256, HS384, HS512)"
echo "  - ✅ ECDSA (ES256, ES384, ES512)"
echo "  - ❌ RSASSA-PSS (PS256, PS384, PS512)"
echo "- ✅ Allow users to provide keys"
echo "- ✅ Allow users to have Vault generate keys"
echo "- ✅ Arbitrary custom claims"
echo "- ✅ Nested custom claims"
echo "- ✅ Automatically specified expiration, issued time, and JWT ID (only exp is actually required by the RFC spec)"
echo "  - ✅ Prevents users from overriding iat, and jti fields"
echo "- ❌ Key lifecycle operations (rotating keys, validating against old keys, etc.)"
echo
echo "Possible features:"
echo "- Generation-time claims. Not-before (nbf) is an obvious example"
echo "- Explicitly invalidate JWTs by ID"
echo "- Look up role name from JWT"
echo "- Templating of custom claims. Ex: '{.RoleName}' for the name of the role"
echo "- Leeway for time skew - ideally shouldn't be an issue, but somehow always is one..."
echo "  - With the library I'm using, this would be problematic as it is a global configuration"
echo
echo
echo "Plugin Repo: https://github.com/pcman312/vault-plugin-secrets-jwt"
echo "JWT lib:     https://github.com/dgrijalva/jwt-go"
echo
echo "Thank you!"
