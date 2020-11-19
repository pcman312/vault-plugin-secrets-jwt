package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	JWT "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *Backend) operationValidateToken(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve role: %w", err)
	}

	if role == nil {
		return nil, nil
	}

	rawToken := data.Get("token").(string)

	token, err := validateJWT(role, rawToken)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}

	respData := map[string]interface{}{
		"claims": token.Claims,
	}

	ttl, ok := getTTL(token.Claims)
	if ok {
		respData["ttl"] = ttl.String()
	}

	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

func validateJWT(role Role, rawToken string) (*JWT.Token, error) {
	return JWT.Parse(rawToken, role.Validate())
}

func getTTL(claims JWT.Claims) (ttl time.Duration, ok bool) {
	mapClaims, ok := claims.(JWT.MapClaims)
	if !ok {
		return 0, false
	}
	exp, ok := getInt64(mapClaims, "exp")
	if !ok {
		return 0, false
	}

	expTime := time.Unix(exp, 0)
	ttl = expTime.Sub(time.Now())
	return ttl, true
}

func getInt64(m map[string]interface{}, key string) (int64, bool) {
	rawVal, ok := m[key]
	if !ok {
		return 0, false
	}

	switch val := rawVal.(type) {
	case int:
		return int64(val), true
	case int32:
		return int64(val), true
	case int64:
		return val, true
	case json.Number:
		i, err := val.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	}
	return 0, false
}
