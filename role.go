package jwt

import (
	"context"
	"encoding/json"
	"fmt"

	JWT "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/tidwall/gjson"
)

const (
	// Standard claims
	IssuerClaim         = "iss"
	SubjectClaim        = "sub"
	AudienceClaim       = "aud"
	ExpirationTimeClaim = "exp"
	NotBeforeClaim      = "nbf"
	IssuedAtClaim       = "iat"
	JWTIDClaim          = "jti"
)

// roleConstructor constructs a new role based on the provided values
type roleConstructor func(roleName string, alg string, claims JWT.MapClaims, rawKey []byte) (Role, error)

// newRoleFunc returns a new instance of the role. This is primarily used
// for marshalling/unmarshalling so we don't have to use reflection
type newRoleFunc func() Role

type roleType struct {
	constructor roleConstructor
	new         newRoleFunc
}

var (
	roleAlgMapping = map[string]roleType{
		// RSA signing methods
		JWT.SigningMethodRS256.Alg(): {
			constructor: newRSARole,
			new:         rsaRole,
		},
		JWT.SigningMethodRS384.Alg(): {
			constructor: newRSARole,
			new:         rsaRole,
		},
		JWT.SigningMethodRS512.Alg(): {
			constructor: newRSARole,
			new:         rsaRole,
		},

		// HMAC signing methods
		JWT.SigningMethodHS256.Alg(): {
			constructor: newHMACRole,
			new:         hmacRole,
		},
		JWT.SigningMethodHS384.Alg(): {
			constructor: newHMACRole,
			new:         hmacRole,
		},
		JWT.SigningMethodHS512.Alg(): {
			constructor: newHMACRole,
			new:         hmacRole,
		},

		// ECDSA signing methods
		JWT.SigningMethodES256.Alg(): {
			constructor: newECDSARole,
			new:         ecdsaRole,
		},
		JWT.SigningMethodES384.Alg(): {
			constructor: newECDSARole,
			new:         ecdsaRole,
		},
		JWT.SigningMethodES512.Alg(): {
			constructor: newECDSARole,
			new:         ecdsaRole,
		},
	}

	supportedSigningMethods = getKeysMap(roleAlgMapping)
)

func getKeysMap(m map[string]roleType) map[string]bool {
	result := make(map[string]bool, len(m))
	for k := range m {
		result[k] = true
	}
	return result
}

type Role interface {
	Name() string
	Claims() JWT.MapClaims
	SigningMethod() string

	// SigningKey returns the key used to sign the JWT
	SigningKey() interface{}

	// Validate returns the function used to return the key used to validate the JWT
	Validate() JWT.Keyfunc

	// KeyString returns a string describing the key specified in the role.
	// This is used when performing a read on the role
	KeyString() string

	// SetClaims when updating the role. This should ignore current claims and replace them with the provided set
	SetClaims(claims JWT.MapClaims) error

	// GenerateJWT() (rawToken string, err error)
	// ValidateJWT(rawToken string) (*JWT.Token, error)
}

// newRole constructs a new role based on the `alg` type specified
func newRole(roleName string, alg string, data *framework.FieldData) (Role, error) {
	rt, ok := roleAlgMapping[alg]
	if !ok {
		return nil, fmt.Errorf("unsupported signing method: %s", alg)
	}

	claims, err := getClaims(roleName, data.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to determine claims: %w", err)
	}

	var rawKey []byte
	k, ok := data.GetOk("key")
	if ok {
		rawKey = []byte(k.(string))
	}

	return rt.constructor(roleName, alg, claims, rawKey)
}

// getRole from Vault storage
func getRole(ctx context.Context, store logical.Storage, name string) (Role, error) {
	entry, err := store.Get(ctx, fmt.Sprintf("roles/%s", name))
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve role: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	alg := gjson.GetBytes(entry.Value, "alg").String()

	rt, ok := roleAlgMapping[alg]
	if !ok {
		return nil, fmt.Errorf("unsupported signing method: %s", alg)
	}

	role := rt.new()
	err = json.Unmarshal(entry.Value, role)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal role from storage: %w", err)
	}
	return role, nil
}

// storeRole into Vault storage
func storeRole(ctx context.Context, store logical.Storage, role Role) error {
	roleBytes, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("failed to marshal role for storage: %w", err)
	}

	entry := &logical.StorageEntry{
		Key:   fmt.Sprintf("roles/%s", role.Name()),
		Value: roleBytes,
	}
	return store.Put(ctx, entry)
}
