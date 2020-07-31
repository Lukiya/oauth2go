package oauth2go

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/security"
	"github.com/Lukiya/oauth2go/store"
	"github.com/Lukiya/oauth2go/token"
	"github.com/dgrijalva/jwt-go"
	log "github.com/syncfuture/go/slog"
	"github.com/valyala/fasthttp"
)

type AuthServerOptions struct {
	AuthCookieName         string
	AuthorizeEndpoint      string
	TokenEndpoint          string
	LoginEndpoint          string
	PkceRequired           bool
	PrivateKey             *rsa.PrivateKey
	ClientStore            store.IClientStore
	TokenStore             store.ITokenStore
	AuthorizationCodeStore store.IAuthorizationCodeStore
	ClientValidator        security.IClientValidator
	AuthCodeGenerator      token.IAuthCodeGenerator
	TokenGenerator         token.ITokenGenerator
	ClaimsGenerator        token.ITokenClaimsGenerator
}

func NewDefaultAuthServer(options *AuthServerOptions) IAuthServer {
	if options.ClientStore == nil {
		log.Fatal("ClientStore cannot be nil")
	}
	if options.TokenStore == nil {
		log.Fatal("TokenStore cannot be nil")
	}
	if options.PrivateKey == nil {
		log.Fatal("PrivateKey cannot be nil")
	}
	if options.ClaimsGenerator == nil {
		log.Fatal("ClaimsGenerator cannot be nil")
	}
	if options.AuthCookieName == "" {
		options.AuthCookieName = "OAuth"
	}
	if options.AuthorizeEndpoint == "" {
		options.AuthorizeEndpoint = "/connect/authorize"
	}
	if options.TokenEndpoint == "" {
		options.TokenEndpoint = "/connect/token"
	}
	if options.LoginEndpoint == "" {
		options.LoginEndpoint = "/account/login"
	}

	if options.AuthorizationCodeStore == nil {
		options.AuthorizationCodeStore = store.NewDefaultAuthorizationCodeStore(60)
	}
	if options.ClientValidator == nil {
		options.ClientValidator = security.NewDefaultClientValidator(options.ClientStore)
	}
	if options.AuthCodeGenerator == nil {
		options.AuthCodeGenerator = token.NewDefaultAuthCodeGenerator()
	}
	if options.TokenGenerator == nil {
		options.TokenGenerator = token.NewDefaultTokenGenerator(
			options.PrivateKey,
			jwt.SigningMethodPS256.SigningMethodRSA,
			options.ClaimsGenerator,
		)
	}

	return &DefaultAuthServer{
		AuthCookieName:         options.AuthCookieName,
		AuthorizeEndpoint:      options.AuthorizeEndpoint,
		TokenEndpoint:          options.TokenEndpoint,
		LoginEndpoint:          options.LoginEndpoint,
		PkceRequired:           options.PkceRequired,
		ClientStore:            options.ClientStore,
		TokenStore:             options.TokenStore,
		AuthorizationCodeStore: options.AuthorizationCodeStore,
		ClientValidator:        options.ClientValidator,
		AuthCodeGenerator:      options.AuthCodeGenerator,
		TokenGenerator:         options.TokenGenerator,
	}
}

type DefaultAuthServer struct {
	AuthCookieName         string
	AuthorizeEndpoint      string
	TokenEndpoint          string
	LoginEndpoint          string
	PkceRequired           bool
	ClientStore            store.IClientStore
	TokenStore             store.ITokenStore
	AuthorizationCodeStore store.IAuthorizationCodeStore
	ClientValidator        security.IClientValidator
	AuthCodeGenerator      token.IAuthCodeGenerator
	TokenGenerator         token.ITokenGenerator
}

// AuthorizeRequestHandler handle authorize request
func (x *DefaultAuthServer) AuthorizeRequestHandler(ctx *fasthttp.RequestCtx) {
	respType := string(ctx.FormValue(core.Form_ResponseType))
	clientID := string(ctx.FormValue(core.Form_ClientID))
	redirectURI := string(ctx.FormValue(core.Form_RedirectUri))
	scopesStr := string(ctx.FormValue(core.Form_Scope))
	state := string(ctx.FormValue(core.Form_State))

	// verify client
	client, err, errDesc := x.ClientValidator.VerifyClient4(
		clientID,
		respType,
		redirectURI,
		scopesStr,
		state,
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	switch respType {
	case core.ResponseType_Code:
	}

	switch respType {
	case core.ResponseType_Code:
		x.AuthorizationCodeRequestHandler(ctx, client, respType, scopesStr, redirectURI, state)
	case core.ResponseType_Token:
		x.ImplicitTokenRequestHandler(ctx, client, respType, scopesStr, redirectURI, state)
	}
}

// AuthorizationCodeRequestHandler handle authorize code request
func (x *DefaultAuthServer) AuthorizationCodeRequestHandler(ctx *fasthttp.RequestCtx, client model.IClient, respType, scopesStr, redirectURI, state string) {
	username := core.GetCookieValue(ctx, "Username")
	if username == "" {
		// redirect to login page
		returnURL := core.MakeURLStr(x.AuthorizeEndpoint, &map[string]string{
			core.Form_ClientID:     client.GetID(),
			core.Form_RedirectUri:  redirectURI,
			core.Form_ResponseType: respType,
			core.Form_Scope:        scopesStr,
			core.Form_State:        state,
		})
		targetURL := core.MakeURLStr(x.LoginEndpoint, &map[string]string{core.Form_ReturnUrl: returnURL})
		core.Redirect(ctx, targetURL)
		return
	}

	var code string
	// pkce check
	if !x.PkceRequired {
		// pkce not required, just issue code
		code = x.AuthCodeGenerator.Generate()
		x.AuthorizationCodeStore.Save(
			code,
			&model.TokenRequestInfo{
				ClientID:    client.GetID(),
				Scopes:      scopesStr,
				RedirectUri: redirectURI,
				Username:    username,
			},
		)
		targetURL := fmt.Sprintf("%s?%s=%s&%s=%s",
			redirectURI,
			core.Form_Code,
			code,
			core.Form_State,
			url.QueryEscape(state),
		)
		core.Redirect(ctx, targetURL)
		return
	}

	// pkce required
	codeChanllenge := string(ctx.FormValue(core.Form_CodeChallenge))

	if codeChanllenge == "" {
		// client didn't provide pkce chanllenge, write error
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_invalid_request), errors.New("code chanllenge is required"))
		return
	}

	// client provided pkce chanllenge
	codeChanllengeMethod := string(ctx.FormValue(core.Form_CodeChallengeMethod))
	if codeChanllengeMethod == "" {
		codeChanllengeMethod = core.Pkce_Plain
	} else if codeChanllengeMethod != core.Pkce_Plain && codeChanllengeMethod != core.Pkce_S256 {
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_invalid_request), errors.New("transform algorithm not supported"))
		return
	}

	// issue authorization code
	code = x.AuthCodeGenerator.Generate()
	x.AuthorizationCodeStore.Save(
		code,
		&model.TokenRequestInfo{
			ClientID:    client.GetID(),
			Scopes:      scopesStr,
			RedirectUri: redirectURI,
			Username:    username,
		},
	)

	targetURL := fmt.Sprintf("%s?%s=%s&%s=%s&%s=%s&%s=%s",
		redirectURI,
		core.Form_Code,
		code,
		core.Form_State,
		url.QueryEscape(state),
		core.Form_CodeChallenge,
		url.QueryEscape(codeChanllenge),
		core.Form_CodeChallengeMethod,
		codeChanllengeMethod,
	)
	core.Redirect(ctx, targetURL)
}

// AuthorizationCodeRequestHandler handle implicit token request
func (x *DefaultAuthServer) ImplicitTokenRequestHandler(ctx *fasthttp.RequestCtx, client model.IClient, respType, scopesStr, redirectURI, state string) {
	username := core.GetCookieValue(ctx, x.AuthCookieName)
	if username == "" {
		// redirect to login page
		a := core.MakeURLStr(x.AuthorizeEndpoint, &map[string]string{
			core.Form_ClientID:     client.GetID(),
			core.Form_RedirectUri:  redirectURI,
			core.Form_ResponseType: respType,
			core.Form_Scope:        scopesStr,
			core.Form_State:        state,
		})
		targetURL := core.MakeURLStr(x.LoginEndpoint, &map[string]string{core.Form_ReturnUrl: a})
		core.Redirect(ctx, targetURL)
		return
	}

	// user already logged in, issue token
	accessToken, err := x.TokenGenerator.GenerateAccessToken(
		ctx,
		core.GrantType_Implicit,
		client,
		strings.Split(scopesStr, core.Seperator_Scope),
		username,
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_server_error), err)
		return
	}

	targetURL := fmt.Sprintf("%s?%s=%s&%s=%s&%s=%d&%s=%s&%s=%s",
		redirectURI,
		core.Form_AccessToken,
		accessToken,
		core.Form_TokenType,
		core.Form_TokenTypeBearer,
		core.Form_ExpiresIn,
		client.GetAccessTokenExpireSeconds(),
		core.Form_Scope,
		url.QueryEscape(scopesStr),
		core.Form_State,
		url.QueryEscape(state),
	)

	core.Redirect(ctx, targetURL)
}

// TokenRequestHandler handle token request
func (x *DefaultAuthServer) TokenRequestHandler(ctx *fasthttp.RequestCtx) {
	// get parametes from request
	var grantTypeStr = string(ctx.FormValue(core.Form_GrantType))
	var scopesStr = string(ctx.FormValue(core.Form_Scope))

	credentials, err, errDesc := x.ClientValidator.ExractClientCredentials(ctx)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// verify client
	var client model.IClient
	if grantTypeStr == core.GrantType_AuthorizationCode {
		// auth code grant doesn't post scopes
		client, err, errDesc = x.ClientValidator.VerifyClient2(credentials, grantTypeStr)
	} else {
		// other scopes must post scopes
		client, err, errDesc = x.ClientValidator.VerifyClient3(credentials, grantTypeStr, scopesStr)
	}

	if err != nil {
		var httpStatusCode int
		if err.Error() == core.Err_invalid_client {
			httpStatusCode = http.StatusUnauthorized
		} else {
			httpStatusCode = http.StatusBadRequest
		}
		x.writeError(ctx, httpStatusCode, err, errDesc)
		return
	}

	switch grantTypeStr {
	case core.GrantType_Client:
		x.HandleClientCredentialsTokenRequest(ctx, client, scopesStr)
	case core.GrantType_AuthorizationCode:
	case core.GrantType_ResourceOwner:
	case core.GrantType_RefreshToken:
	default:
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_unsupported_grant_type), nil)
	}
}

// HandleClientCredentialsTokenRequest handle client credentials token request
func (x *DefaultAuthServer) HandleClientCredentialsTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient, scopesStr string) {
	// issue token directly
	token, err := x.TokenGenerator.GenerateAccessToken(
		ctx,
		core.GrantType_Implicit,
		client,
		strings.Split(scopesStr, core.Seperator_Scope),
		client.GetID(),
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_server_error), err)
		return
	}

	x.writeToken(ctx, token, scopesStr, client.GetAccessTokenExpireSeconds(), "")
}

// HandleAuthorizationCodeTokenRequest handle authorization code token request
func (x *DefaultAuthServer) HandleAuthorizationCodeTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient) {
}

// HandleResourceOwnerTokenRequest handle resource owner token request
func (x *DefaultAuthServer) HandleResourceOwnerTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient, scopesStr string) {
}

// HandleRefreshTokenRequest handle refresh token request
func (x *DefaultAuthServer) HandleRefreshTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient) {
}

// WriteTokenHandler
func (x *DefaultAuthServer) writeToken(ctx *fasthttp.RequestCtx, token, scopesStr string, expireSeconds int32, refreshToken string) {
	ctx.SetContentType(core.ContentType_Json)
	ctx.Response.Header.Add(core.Header_CacheControl, core.Header_CacheControl_Value)
	ctx.Response.Header.Add(core.Header_Pragma, core.Header_Pragma_Value)

	if refreshToken == "" {
		ctx.WriteString(fmt.Sprintf(core.Format_Token1, token, expireSeconds, scopesStr))
	} else {
		ctx.WriteString(fmt.Sprintf(core.Format_Token2, token, refreshToken, expireSeconds, scopesStr))
	}
}

// writeError handle error
func (x *DefaultAuthServer) writeError(ctx *fasthttp.RequestCtx, statusCode int, err, errDesc error) {
	if errDesc == nil {
		errDesc = err
	}

	ctx.SetStatusCode(statusCode)
	ctx.SetContentType(core.ContentType_Json)
	ctx.Response.Header.Add(core.Header_CacheControl, core.Header_CacheControl_Value)
	ctx.Response.Header.Add(core.Header_Pragma, core.Header_Pragma_Value)

	ctx.WriteString(fmt.Sprintf(core.Format_Error, err.Error(), errDesc.Error()))
}
