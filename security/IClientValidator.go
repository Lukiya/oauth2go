package security

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/store"
	log "github.com/syncfuture/go/slog"
	"github.com/syncfuture/go/u"
	"github.com/valyala/fasthttp"
)

type IClientValidator interface {
	// ExractClientCredentials extract client credential from request
	ExractClientCredentials(ctx *fasthttp.RequestCtx) (*model.Credential, error, error)
	// VerifyClient1 verify client id & secret
	VerifyClient1(credential *model.Credential) (model.IClient, error, error)
	// VerifyClient2 verify client id, secret & grant type
	VerifyClient2(credential *model.Credential, grantType string) (model.IClient, error, error)
	// VerifyClient3 verify client id, secret, grant type & scopes
	VerifyClient3(credential *model.Credential, grantType, scopesStr string) (model.IClient, error, error)
	// VerifyClient4 verify client id & secret, response type, scopes, redirect uri
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

// ExractClientCredentials extract client credential from request
func (x *DefaultClientValidator) ExractClientCredentials(ctx *fasthttp.RequestCtx) (r *model.Credential, err, errDesc error) {
	r, err, errDesc = x.exractClientCredentialsFromHeader(ctx)
	if err == nil {
		return
	}

	r, err, errDesc = x.exractClientCredentialsFromBody(ctx)
	return
}

func (x *DefaultClientValidator) exractClientCredentialsFromHeader(ctx *fasthttp.RequestCtx) (r *model.Credential, err, errDesc error) {
	authorzation := string(ctx.Request.Header.Peek(core.Header_Authorization))
	if authorzation == "" {
		err = errors.New(core.Err_invalid_request)
		errDesc = errors.New("no authorization header")
		log.Warn(errDesc.Error())
		return
	}

	authArray := strings.Split(authorzation, core.Seperator_Scope)
	if len(authArray) != 2 || authArray[1] == "" {
		err = errors.New(core.Err_invalid_request)
		errDesc = errors.New("invalid authorization header format")
		log.Warn(errDesc.Error())
		return
	}

	authBytes, err := base64.URLEncoding.DecodeString(authArray[1])
	if u.LogError(err) {
		return
	}
	authStr := string(authBytes)
	authArray = strings.Split(authStr, core.Seperators_Auth)

	if len(authArray) != 2 || authArray[0] == "" || authArray[1] == "" {
		err = errors.New(core.Err_invalid_request)
		errDesc = errors.New("invalid authorization header segments length")
		log.Warn(errDesc.Error())
		return
	}

	r = &model.Credential{
		Username: authArray[0],
		Password: authArray[1],
	}
	return
}

func (x *DefaultClientValidator) exractClientCredentialsFromBody(ctx *fasthttp.RequestCtx) (r *model.Credential, err error, errDesc error) {
	id := string(ctx.FormValue(core.Form_ClientID))

	if id == "" {
		err = errors.New(core.Err_invalid_request)
		errDesc = errors.New("client id is missing")
		log.Warn(errDesc.Error())
		return
	}

	secret := string(ctx.FormValue(core.Form_ClientSecret))
	if secret == "" {
		err = errors.New(core.Err_invalid_request)
		errDesc = errors.New("client secret is missing")
		log.Warn(errDesc.Error())
		return
	}

	r = &model.Credential{
		Username: id,
		Password: secret,
	}
	return
}

// VerifyClient1 verify client id & secret
func (x *DefaultClientValidator) VerifyClient1(credential *model.Credential) (model.IClient, error, error) {
	client := x.ClientStore.GetClient(credential.Username)

	if client == nil {
		err := errors.New(core.Err_invalid_client)
		errDesc := errors.New("client not exists")
		log.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	if credential.Password != client.GetSecret() {
		err := errors.New(core.Err_invalid_client)
		errDesc := errors.New("invalid client")
		log.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	return client, nil, nil

}

// VerifyClient2 verify client id, secret & grant type
func (x *DefaultClientValidator) VerifyClient2(credential *model.Credential, grantType string) (model.IClient, error, error) {
	if grantType == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("invalid client")
		log.Warn(errDesc.Error())
		return nil, err, errDesc
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
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("scope is missing")
		log.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	client, err, errDesc := x.VerifyClient2(credential, grantType)
	if err != nil {
		return nil, err, errDesc
	}

	err, errDesc = x.validateScopes(client, scopesStr)
	if err != nil {
		return nil, err, errDesc
	}

	return client, nil, nil
}

// VerifyClient4 verify client id & secret, response type, scopes, redirect uri
func (x *DefaultClientValidator) VerifyClient4(clientID, responseType, redirectURI, scopesStr, state string) (model.IClient, error, error) {
	if clientID == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("client id is missing")
		log.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	if responseType == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("response type is missing")
		log.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	if redirectURI == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("redirect uri is missing")
		log.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	if scopesStr == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("scope is missing")
		log.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	client := x.ClientStore.GetClient(clientID)

	if client == nil {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("client not exists")
		log.Warn(errDesc.Error())
		return nil, err, errDesc
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

	err := errors.New(core.Err_unauthorized_client)
	errDesc := fmt.Errorf("'%s' grant is not allowed for '%s'", grantType, client.GetID())
	log.Warn(errDesc.Error())
	return err, errDesc
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

	err := errors.New(core.Err_unauthorized_client)
	errDesc := fmt.Errorf("'%s' scope is not allowed for '%s'", scope, client.GetID())
	log.Warn(errDesc.Error())
	return err, errDesc
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

	err := errors.New(core.Err_unauthorized_client)
	errDesc := fmt.Errorf("'%s' redirect uri is is not allowed for '%s'", redirectURI, client.GetID())
	log.Warn(errDesc.Error())
	return err, errDesc
}

func (x *DefaultClientValidator) validateResponseType(client model.IClient, responseType string) (error, error) {
	if responseType == core.ResponseType_Code {
		return x.validateGrants(client, core.GrantType_AuthorizationCode)
	} else if responseType == core.ResponseType_Token {
		return x.validateGrants(client, core.GrantType_Implicit)
	}

	err := errors.New(core.Err_unauthorized_client)
	errDesc := fmt.Errorf("'%s' response type is is not allowed for '%s'", responseType, client.GetID())
	log.Warn(errDesc.Error())
	return err, errDesc
}
