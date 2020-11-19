package jwt

import (
	"context"
	"fmt"
	"time"

	JWT "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *Backend) operationGenerateToken(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve role: %w", err)
	}

	if role == nil {
		return nil, nil
	}

	token, err := generateJWT(role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"token": token,
		},
	}
	return resp, nil
}

func generateJWT(role Role) (token string, err error) {
	if role.SigningMethod() == "" {
		return "", fmt.Errorf("missing signing method")
	}

	claims := copyClaims(role.Claims())

	now := time.Now()
	claims[IssuedAtClaim] = now.Unix()

	jti, err := uuid.GenerateUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT ID: %w", err)
	}
	claims[JWTIDClaim] = jti

	// Convert `exp` to an actual expiration time
	rawExp := claims[ExpirationTimeClaim].(string)
	expDur, err := time.ParseDuration(rawExp)
	if err != nil {
		return "", fmt.Errorf("invalid expiration time: %w", err)
	}

	exp := now.Add(expDur)
	claims[ExpirationTimeClaim] = exp.Unix()

	alg := JWT.GetSigningMethod(role.SigningMethod())
	if alg == nil {
		return "", fmt.Errorf("unrecognized signing method: %s", alg)
	}

	t := JWT.NewWithClaims(alg, claims)
	token, err = t.SignedString(role.SigningKey())
	if err != nil {
		return "", err
	}
	return token, nil
}
