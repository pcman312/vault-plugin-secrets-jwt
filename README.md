# vault-plugin-secrets-jwt
A Vault secrets engine for generating and validating JWTs.

## Usage

1. Register the plugin via [Vault's plugin system](https://www.vaultproject.io/docs/internals/plugins.html)
2. Enable the engine:
   ```shell script
   $ vault secrets enable -path=jwt vault-plugin-secrets-jwt
   Success! Enabled the vault-plugin-secrets-jwt secrets engine at: jwt/
   ```
3. Configure a role. You must specify two fields:
   - `alg`: The signing algorithm to use. Allowed values: `RS256`, `RS384`, `RS512`, `HS256`, `HS384`,
     `HS512`, `ES256`, `ES384`, `ES512`. This is case-insensitive.
   - `exp`: The amount of time before a JWT expires. Unlike in an actual JWT, this is the duration that the JWT
     should live. This can be either an integer indicating a number of seconds, or use a suffix notation such as `1h`
   
   You may specify any arbitrary key/value pairs you wish.
   
   ```shell script
   $ vault write jwt/roles/myrole/config alg=RS512 exp=1h foo=bar bar=baz
   Success! Data written to: jwt/roles/myrole/config
   ```
4. Generate a JWT
   ```shell script
   $ vault read jwt/roles/myrole/generate
   Key      Value
   ---      -----
   token    eyJhbGciOiJSUzUxM <shortened for brevity> oN6s7FfP4NuFc-K1yg
   ```
5. Validate a JWT
   ```shell script
   $ vault write jwt/roles/myrole/validate token="${TOKEN}"
   Key       Value
   ---       -----
   claims    map[bar:baz exp:1605829718 foo:bar iat:1605826118 iss:vault/myrole jti:34e888e2-22f1-4f96-f22e-8ef1894aed42]
   ```

## Endpoints

### `/roles/{name}/config`
Configures a JWT role. Generates an RSA key by default.

Allows user to specify any key/value pairs to include in the JWT.

When read, only the public key will be returned (or the key redacted if a symmetric key).
This is to protect the key from access by users who shouldn't be able to see it.
Key-exporting is not supported. If you need the key outside of this engine, generate it and
provide it rather than having the engine generate one. 

### `/roles/{name}/generate`
Generates a JWT & returns it as a secret.

### `/roles/{name}/validate`
Validates a provided JWT against the role specified

## Features/TODO list
- [x] Certain fields will need to be explicitly specified types:
  - `exp` - Duration (creation + this value => JWT expiration)
- [x] Validation of key/value pairs against default types
  - [x] Not allowed:
    - `jti` (JWT ID)
    - `iat` (Issued At)
  - [x] Defaults:
    - `iss` - `"vault/{name}"` where `{name}` is the name of the role?
- [x] Allow user to provide key
- [x] Generate keys when one isn't provided
  - [x] RSA
  - [x] HMAC
  - [x] ECDSA
- [x] Supported key types
  - [x] RSA   (RS256, RS384, RS512)
  - [x] HMAC  (HS256, HS384, HS512)
  - [x] ECDSA (ES256, ES384, ES512)
- [ ] Logging?
- [ ] Key lifecycle
  - [ ] Replace an existing key
  - [ ] Allow validation with an old key for a configurable amount of time?
- [ ] Allow for time skewing
  - This one is potentially problematic with the library I'm using here since it is configured
    with a global TimeFunc variable.

## Possible features
- Allow generation-time claims? `nbf` comes to mind, but possibly allow other fields? This would
  allow JWTs to be configurable during generation. We would probably need to have some protections
  that the operator can specify on what fields can be specified & maybe what values in each
  field can be used.
- Allow users to invalidate specific JWTs based on the JWT ID field (`jti`)
  Ex: `/roles/{name}/invalidate/{jti}`
- An endpoint that returns the role name of the provided JWT
- Templating within fields. Ex: `{.RoleName}` for the name of the role in Vault
