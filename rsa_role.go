package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	JWT "github.com/dgrijalva/jwt-go"
)

var _ Role = (*RSARole)(nil)

type RSARole struct {
	RoleName   string        `json:"name"`
	Key        rsaKey        `json:"key"`
	SignMethod string        `json:"alg"`
	JWTClaims  JWT.MapClaims `json:"claims"`
}

func newRSARole(roleName string, alg string, claims JWT.MapClaims, rawKey []byte) (Role, error) {
	var key *rsa.PrivateKey
	if rawKey != nil {
		// Key is specified, use it
		rkey, err := parseRSAKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key: %w", err)
		}
		key = rkey
	} else {
		// Key isn't specified - generate one
		rkey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		key = rkey
	}

	role := &RSARole{
		RoleName:   roleName,
		Key:        rsaKey{key},
		SignMethod: alg,
		JWTClaims:  claims,
	}
	return role, nil
}

func rsaRole() Role {
	return &RSARole{}
}

func (r *RSARole) SetClaims(claims JWT.MapClaims) error {
	r.JWTClaims = claims
	return nil
}

func (r *RSARole) Name() string {
	return r.RoleName
}

func (r *RSARole) Claims() JWT.MapClaims {
	return r.JWTClaims
}

func (r *RSARole) SigningMethod() string {
	return r.SignMethod
}

func (r *RSARole) KeyString() string {
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&r.Key.PublicKey),
	}
	b := pem.EncodeToMemory(block)
	return string(b)
}

func (r *RSARole) SigningKey() interface{} {
	return r.Key.PrivateKey
}

func (r *RSARole) Validate() JWT.Keyfunc {
	return func(t *JWT.Token) (interface{}, error) {
		return r.Key.Public(), nil
	}
}

type rsaKey struct {
	*rsa.PrivateKey
}

func (r rsaKey) MarshalJSON() ([]byte, error) {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(r.PrivateKey),
	}
	b := pem.EncodeToMemory(block)
	enc, err := json.Marshal(string(b))
	if err != nil {
		return nil, err
	}
	return enc, nil
}

func (r *rsaKey) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	key, err := parseRSAKey([]byte(str))
	if err != nil {
		return err
	}
	r.PrivateKey = key
	return nil
}

func parseRSAKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("invalid pem block")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("pem block is not 'RSA PRIVATE KEY'")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}
