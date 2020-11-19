package jwt

import (
	"fmt"

	JWT "github.com/dgrijalva/jwt-go"
)

var (
	unacceptableClaims = []string{
		JWTIDClaim,
		IssuedAtClaim,
	}

	ignoredClaims = map[string]bool{
		"name": true,
		"alg":  true,
		"key":  true,
	}
)

func getClaims(roleName string, raw map[string]interface{}) (claims JWT.MapClaims, err error) {
	for _, key := range unacceptableClaims {
		_, exists := raw[key]
		if exists {
			return nil, fmt.Errorf("cannot specify reserved claim %s", key)
		}
	}

	claimsMap := map[string]interface{}{}

	for k, v := range raw {
		// Skip fields that aren't meant to be claims
		if ignoredClaims[k] {
			continue
		}

		claimsMap[k] = v
	}

	if _, ok := claimsMap[IssuerClaim]; !ok {
		claimsMap[IssuerClaim] = fmt.Sprintf("vault/%s", roleName)
	}

	return claimsMap, nil
}

func copyClaims(m JWT.MapClaims) JWT.MapClaims {
	cpy := make(map[string]interface{}, len(m))

	for k, v := range m {
		cpy[k] = v
	}
	return cpy
}
