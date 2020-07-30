package security

import (
	"errors"
	"fmt"

	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/store"
)

type IClientValidator interface {
	ExractClientCredentials() (*model.Credential, error)
	VerifyClient1(credential *model.Credential) (model.IClient, error, error)
	VerifyClient2(credential *model.Credential, grantType string) (model.IClient, error, error)
	VerifyClient3(credential *model.Credential, grantType, scopesStr string) (model.IClient, error, error)
	VerifyClient4(clientID, responseType, redirectURI, scopesStr, state string) (model.IClient, error, error)
}

func NewDefaultClientValidator(clientStore store.IClientStore) IClientValidator {
	return &DefaultClientValidator{
		ClientStore: clientStore,
	}
}

type DefaultClientValidator struct {
	ClientStore store.IClientStore
}

func (x *DefaultClientValidator) ExractClientCredentials() (*model.Credential, error) {
	return nil, nil
}

// VerifyClient1 verify client id & secret
func (x *DefaultClientValidator) VerifyClient1(credential *model.Credential) (model.IClient, error, error) {
	client := x.ClientStore.GetClient(credential.Username)

	if client == nil {
		return nil, errors.New(core.Err_invalid_client), errors.New("client not exists")
	}

	if credential.Password != client.GetSecret() {
		return nil, errors.New(core.Err_invalid_client), errors.New("invalid client")
	}

	return client, nil, nil

}

// VerifyClient2 verify client id, secret & grant type
func (x *DefaultClientValidator) VerifyClient2(credential *model.Credential, grantType string) (model.IClient, error, error) {
	if grantType == "" {
		return nil, errors.New(core.Err_invalid_request), errors.New("grant type is missing")
	}

	client, err, errDesc := x.VerifyClient1(credential)
	if err != nil {
		return nil, err, errDesc
	}

	err, errDesc = x.validateGrants(client, grantType)
	if err != nil {
		return nil, err, errDesc
	}

	return client, nil, nil

}

// VerifyClient3 verify client id, secret, grant type & scopes
func (x *DefaultClientValidator) VerifyClient3(credential *model.Credential, grantType, scopesStr string) (model.IClient, error, error) {
	if scopesStr == "" {
		return nil, errors.New(core.Err_invalid_request), errors.New("scope is missing")
	}

	client, err, errDesc := x.VerifyClient2(credential, grantType)
	if err != nil {
		return nil, err, errDesc
	}

	err, errDesc = x.validateScopes(client, grantType)
	if err != nil {
		return nil, err, errDesc
	}

	return client, nil, nil
}

// VerifyClient4 verify client id & secret, response type, scopes, redirect uri
func (x *DefaultClientValidator) VerifyClient4(clientID, responseType, redirectURI, scopesStr, state string) (model.IClient, error, error) {
	if clientID == "" {
		return nil, errors.New(core.Err_invalid_request), errors.New("client id is missing")
	}

	if responseType == "" {
		return nil, errors.New(core.Err_invalid_request), errors.New("response type is missing")
	}

	if redirectURI == "" {
		return nil, errors.New(core.Err_invalid_request), errors.New("redirect uri is missing")
	}

	if scopesStr == "" {
		return nil, errors.New(core.Err_invalid_request), errors.New("scope is missing")
	}

	client := x.ClientStore.GetClient(clientID)

	if client == nil {
		return nil, errors.New(core.Err_invalid_client), errors.New("client not exists")
	}

	err, errDesc := x.validateRedirectUris(client, redirectURI)
	if err != nil {
		return nil, err, errDesc
	}

	err, errDesc = x.validateScopes(client, scopesStr)
	if err != nil {
		return nil, err, errDesc
	}

	err, errDesc = x.validateResponseType(client, responseType)
	if err != nil {
		return nil, err, errDesc
	}

	return client, nil, nil
}

// validateGrants _
func (x *DefaultClientValidator) validateGrants(client model.IClient, grantType string) (error, error) {
	allowedGrants := client.GetGrants()
	if allowedGrants != nil && len(allowedGrants) > 0 {
		for _, allowedGrant := range allowedGrants {
			if allowedGrant == grantType {
				return nil, nil
			}
		}
	}

	return errors.New(core.Err_unauthorized_client), fmt.Errorf("'%s' grant is not allowed for '%s'", grantType, client.GetID())
}

// validateScopes _
func (x *DefaultClientValidator) validateScopes(client model.IClient, scope string) (error, error) {
	allowedScopes := client.GetScopes()
	if allowedScopes != nil && len(allowedScopes) > 0 {
		for _, allowedScope := range allowedScopes {
			if allowedScope == scope {
				return nil, nil
			}
		}
	}

	return errors.New(core.Err_unauthorized_client), fmt.Errorf("'%s' scope is not allowed for '%s'", scope, client.GetID())
}

// validateRedirectUris _
func (x *DefaultClientValidator) validateRedirectUris(client model.IClient, redirectURI string) (error, error) {
	allowedrUris := client.GetRedirectUris()
	if allowedrUris != nil && len(allowedrUris) > 0 {
		for _, allowedrUri := range allowedrUris {
			if allowedrUri == redirectURI {
				return nil, nil
			}
		}
	}

	return errors.New(core.Err_unauthorized_client), fmt.Errorf("'%s' redirect uri is not allowed for '%s'", redirectURI, client.GetID())
}

func (x *DefaultClientValidator) validateResponseType(client model.IClient, responseType string) (error, error) {
	if responseType == core.ResponseType_Code {
		return x.validateGrants(client, core.GrantType_AuthorizationCode)
	} else if responseType == core.ResponseType_Token {
		return x.validateGrants(client, core.GrantType_Implicit)
	}

	return errors.New(core.Err_unauthorized_client), fmt.Errorf("'%s' response type is not supported for '%s'", responseType, client.GetID())
}
