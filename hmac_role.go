package jwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	JWT "github.com/dgrijalva/jwt-go"
)

var _ Role = (*HMACRole)(nil)

type HMACRole struct {
	RoleName   string        `json:"name"`
	Key        []byte        `json:"key"`
	SignMethod string        `json:"alg"`
	JWTClaims  JWT.MapClaims `json:"claims"`
}

func newHMACRole(roleName string, alg string, claims JWT.MapClaims, rawKey []byte) (Role, error) {
	var key []byte
	if len(rawKey) == 0 {
		// Generate a key
		size := 512
		switch alg {
		case JWT.SigningMethodHS256.Alg():
			size = 256
		case JWT.SigningMethodHS384.Alg():
			size = 384
		case JWT.SigningMethodHS512.Alg():
			size = 512
		}
		k, err := generateHMACKey(size)
		if err != nil {
			return nil, fmt.Errorf("failed to generate HMAC key: %w", err)
		}
		key = k
	} else {
		key = rawKey
	}

	role := &HMACRole{
		RoleName:   roleName,
		Key:        key,
		SignMethod: alg,
		JWTClaims:  claims,
	}
	return role, nil
}

func hmacRole() Role {
	return &HMACRole{}
}

func (r HMACRole) Name() string {
	return r.RoleName
}

func (r HMACRole) Claims() JWT.MapClaims {
	return r.JWTClaims
}

func (r HMACRole) SigningMethod() string {
	return r.SignMethod
}

func (r HMACRole) KeyString() string {
	return "[redacted]"
}

func (r HMACRole) SigningKey() interface{} {
	return r.Key
}

func (r HMACRole) Validate() JWT.Keyfunc {
	return func(t *JWT.Token) (interface{}, error) {
		return r.Key, nil
	}
}

func (r HMACRole) SetClaims(claims JWT.MapClaims) error {
	r.JWTClaims = claims
	return nil
}

func generateHMACKey(size int) ([]byte, error) {
	secret := make([]byte, size)
	data := make([]byte, size)
	err := randomBytes(secret)
	if err != nil {
		return nil, err
	}
	err = randomBytes(secret)
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha256.New, secret)
	_, err = h.Write(data)
	if err != nil {
		return nil, err
	}
	str := hex.EncodeToString(h.Sum(nil))
	return []byte(str), nil
}

func randomBytes(b []byte) error {
	expectedN := len(b)
	n, err := rand.Read(b)
	if err != nil {
		return err
	}
	if n != expectedN {
		return fmt.Errorf("failed to read %d bytes: got %d", expectedN, n)
	}
	return nil
}
