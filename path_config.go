package jwt

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *Backend) operationCreateRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := assertFieldsExist(data, "name", "alg", "exp")
	if err != nil {
		return nil, err
	}

	alg, ok := data.Get("alg").(string)
	if !ok {
		return nil, fmt.Errorf("invalid signing algorithm: must be a string")
	}
	alg = strings.ToUpper(alg)

	if !supportedSigningMethods[alg] {
		return nil, fmt.Errorf("unsupported signing method: %s", alg)
	}

	roleName := data.Get("name").(string)

	role, err := newRole(roleName, alg, data)
	if err != nil {
		return nil, err
	}

	err = storeRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("failed to save role: %w", err)
	}

	return nil, nil
}

func (b *Backend) operationUpdateRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := assertFieldsExist(data, "name", "exp")
	if err != nil {
		return nil, err
	}

	err = assertFieldsDoNotExist(data, "alg", "key")
	if err != nil {
		return nil, err
	}

	roleName := data.Get("name").(string)

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve role: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("role doesn't exist")
	}

	claims, err := getClaims(roleName, data.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to determine claims: %w", err)
	}

	err = role.SetClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	err = storeRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("failed to save role: %w", err)
	}
	return nil, nil
}

func (b *Backend) operationReadRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve role: %w", err)
	}

	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"name":   role.Name(),
			"claims": role.Claims(),
			"alg":    role.SigningMethod(),
			"key":    role.KeyString(),
		},
	}
	return resp, nil
}

func (b *Backend) operationDeleteRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	err := req.Storage.Delete(ctx, fmt.Sprintf("roles/%s", roleName))
	if err != nil {
		return nil, fmt.Errorf("failed to delete role: %w", err)
	}
	return nil, nil
}

func assertFieldsExist(data *framework.FieldData, fields ...string) error {
	merr := new(multierror.Error)
	for _, field := range fields {
		if _, ok := data.GetOk(field); !ok {
			merr = multierror.Append(merr, fmt.Errorf("missing field: %q", field))
		}
	}

	return merr.ErrorOrNil()
}

func assertFieldsDoNotExist(data *framework.FieldData, fields ...string) error {
	merr := new(multierror.Error)
	for _, field := range fields {
		if _, ok := data.GetOk(field); ok {
			merr = multierror.Append(merr, fmt.Errorf("field cannot be specified: %q", field))
		}
	}

	return merr.ErrorOrNil()
}
