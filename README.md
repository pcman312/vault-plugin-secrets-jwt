# vault-plugin-secrets-jwt
A Vault secrets engine for generating and validating JWTs.

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
  - [ ] Replace an existing key, but allow for validation with the old one for a certain amount of time?

## Possible features
- [ ] Allow generation-time claims? `nbf` comes to mind, but possibly allow other fields?
      This would allow JWTs to be configurable after configuration.
- [ ] Allow users to invalidate specific JWTs based on the JWT ID field (`jti`) `/roles/{name}/invalidate/{jti}`
- [ ] Add another endpoint that allows you to provide a JWT without knowing the
      role it is associated with? `/validate`
- [ ] Should there be any sort of templating in the values?
      Ex: `{.RoleName}` for the name of the role in Vault?
