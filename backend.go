package jwt

import (
	"context"
	"fmt"

	JWT "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := NewBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type Backend struct {
	*framework.Backend
}

func NewBackend() Backend {
	b := Backend{}
	b.Backend = &framework.Backend{
		Help: "The JWT backend generates & validates JWT tokens.",
		Paths: []*framework.Path{
			&framework.Path{
				Pattern: fmt.Sprintf("roles/%s/config", framework.GenericNameRegex("name")),

				Fields: map[string]*framework.FieldSchema{
					"name": {
						Type:        framework.TypeLowerCaseString,
						Description: "Name of the role",
						Required:    true,
					},
					"alg": {
						Type:        framework.TypeString,
						Description: "Signing algorithm to use",
						AllowedValues: []interface{}{
							JWT.SigningMethodRS256.Alg(),
							JWT.SigningMethodRS384.Alg(),
							JWT.SigningMethodRS512.Alg(),

							JWT.SigningMethodHS256.Alg(),
							JWT.SigningMethodHS384.Alg(),
							JWT.SigningMethodHS512.Alg(),
						},
					},
					"key": {
						Type:        framework.TypeString,
						Description: "Key to use to sign/verify JWTs. If not specified, an RSA key will be generated.",
					},
					"exp": {
						Type:        framework.TypeDurationSecond,
						Description: "How long the JWT lives after its creation time",
						Required:    true,
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.CreateOperation: &framework.PathOperation{
						Callback: b.operationCreateRole,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.operationUpdateRole,
					},
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.operationReadRole,
					},
					logical.DeleteOperation: &framework.PathOperation{
						Callback: b.operationDeleteRole,
					},
				},
				ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
					name := data.Get("name").(string)
					role, err := getRole(ctx, req.Storage, name)
					if err != nil {
						return false, err
					}
					if role == nil {
						return false, nil
					}
					return true, nil
				},

				HelpSynopsis: "Configures a JWT role.",
				HelpDescription: "Before being able to generate JWTs, the backend needs some information about how " +
					"to generate it such as the secret key to use and the fields to include in the claims.",
			},
			&framework.Path{
				Pattern: fmt.Sprintf("roles/%s/generate", framework.GenericNameRegex("name")),

				Fields: map[string]*framework.FieldSchema{
					"name": {
						Type:        framework.TypeLowerCaseString,
						Description: "Name of the role",
						Required:    true,
					},
					// TODO: `nbf`?
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.operationGenerateToken,
					},
				},

				HelpSynopsis: "Configures a JWT role.",
				HelpDescription: "Before being able to generate JWTs, the backend needs some information about how " +
					"to generate it such as the secret key to use and the fields to include in the claims.",
			},
			&framework.Path{
				Pattern: fmt.Sprintf("roles/%s/validate", framework.GenericNameRegex("name")),

				Fields: map[string]*framework.FieldSchema{
					"name": {
						Type:        framework.TypeLowerCaseString,
						Description: "Name of the role",
						Required:    true,
					},
					"token": {
						Type:        framework.TypeString,
						Description: "Token to be validated",
						Required:    true,
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.CreateOperation: &framework.PathOperation{
						Callback: b.operationValidateToken,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.operationValidateToken,
					},
				},

				HelpSynopsis: "Configures a JWT role.",
				HelpDescription: "Before being able to generate JWTs, the backend needs some information about how " +
					"to generate it such as the secret key to use and the fields to include in the claims.",
			},
		},
		BackendType: logical.TypeLogical,
	}
	return b
}
