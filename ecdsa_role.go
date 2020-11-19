package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	JWT "github.com/dgrijalva/jwt-go"
)

var _ Role = (*ECDSARole)(nil)

type ECDSARole struct {
	RoleName   string        `json:"name"`
	Key        ecdsaKey      `json:"key"`
	SignMethod string        `json:"alg"`
	JWTClaims  JWT.MapClaims `json:"claims"`
}

func newECDSARole(roleName string, alg string, claims JWT.MapClaims, rawKey []byte) (Role, error) {
	var key *ecdsa.PrivateKey
	if rawKey != nil {
		// Key is specified, use it
		rkey, err := parseECDSAKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA key: %w", err)
		}
		key = rkey
	} else {
		// Key isn't specified - generate one
		var curve elliptic.Curve
		switch alg {
		case JWT.SigningMethodES256.Alg():
			curve = elliptic.P256()
		case JWT.SigningMethodES384.Alg():
			curve = elliptic.P384()
		case JWT.SigningMethodES512.Alg():
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unable to generate ECDSA key: unsupported curve type")
		}

		rkey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		key = rkey
	}

	role := &ECDSARole{
		RoleName:   roleName,
		Key:        ecdsaKey{key},
		SignMethod: alg,
		JWTClaims:  claims,
	}
	return role, nil
}

func ecdsaRole() Role {
	return &ECDSARole{}
}

func (r *ECDSARole) SetClaims(claims JWT.MapClaims) error {
	r.JWTClaims = claims
	return nil
}

func (r *ECDSARole) Name() string {
	return r.RoleName
}

func (r *ECDSARole) Claims() JWT.MapClaims {
	return r.JWTClaims
}

func (r *ECDSARole) SigningMethod() string {
	return r.SignMethod
}

func (r *ECDSARole) KeyString() string {
	marshalled, err := x509.MarshalPKIXPublicKey(&r.Key.PublicKey)
	if err != nil {
		// TODO: Logging
		return "<unable to get public key>"
	}

	block := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: marshalled,
	}
	b := pem.EncodeToMemory(block)
	return string(b)
}

func (r *ECDSARole) SigningKey() interface{} {
	return r.Key.PrivateKey
}

func (r *ECDSARole) Validate() JWT.Keyfunc {
	return func(t *JWT.Token) (interface{}, error) {
		return r.Key.Public(), nil
	}
}

type ecdsaKey struct {
	*ecdsa.PrivateKey
}

func (k ecdsaKey) MarshalJSON() ([]byte, error) {
	bts, err := x509.MarshalPKCS8PrivateKey(k.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal key: %w", err)
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: bts,
	}
	b := pem.EncodeToMemory(block)

	enc, err := json.Marshal(string(b))
	if err != nil {
		return nil, err
	}
	return enc, nil
}

func (k *ecdsaKey) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return fmt.Errorf("failed to unmarshal key: %w", err)
	}

	key, err := parseECDSAKey([]byte(str))
	if err != nil {
		return err
	}
	k.PrivateKey = key
	return nil
}

func parseECDSAKey(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("invalid pem block")
	}

	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("pem block is not 'EC PRIVATE KEY'")
	}

	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	key, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key in storage: is a %T", rawKey)
	}

	return key, nil
}
