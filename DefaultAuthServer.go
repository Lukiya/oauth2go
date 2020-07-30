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
}

func NewDefaultAuthServer(configs *AuthServerOptions) IAuthServer {
	if configs.ClientStore == nil {
		log.Fatal("ClientStore cannot be nil")
	}
	if configs.TokenStore == nil {
		log.Fatal("TokenStore cannot be nil")
	}
	if configs.PrivateKey == nil {
		log.Fatal("PrivateKey cannot be nil")
	}
	if configs.AuthCookieName == "" {
		configs.AuthCookieName = "OAuth"
	}
	if configs.AuthorizeEndpoint == "" {
		configs.AuthorizeEndpoint = "/connect/authorize"
	}
	if configs.TokenEndpoint == "" {
		configs.TokenEndpoint = "/connect/token"
	}
	if configs.LoginEndpoint == "" {
		configs.LoginEndpoint = "/account/login"
	}

	if configs.AuthorizationCodeStore == nil {
		configs.AuthorizationCodeStore = store.NewDefaultAuthorizationCodeStore(60)
	}
	if configs.ClientValidator == nil {
		configs.ClientValidator = security.NewDefaultClientValidator(configs.ClientStore)
	}
	if configs.AuthCodeGenerator == nil {
		configs.AuthCodeGenerator = token.NewDefaultAuthCodeGenerator()
	}
	if configs.TokenGenerator == nil {
		configs.TokenGenerator = token.NewDefaultTokenGenerator(configs.PrivateKey, jwt.SigningMethodPS256.SigningMethodRSA)
	}

	return &DefaultAuthServer{
		AuthCookieName:         configs.AuthCookieName,
		AuthorizeEndpoint:      configs.AuthorizeEndpoint,
		TokenEndpoint:          configs.TokenEndpoint,
		LoginEndpoint:          configs.LoginEndpoint,
		PkceRequired:           configs.PkceRequired,
		ClientStore:            configs.ClientStore,
		TokenStore:             configs.TokenStore,
		AuthorizationCodeStore: configs.AuthorizationCodeStore,
		ClientValidator:        configs.ClientValidator,
		AuthCodeGenerator:      configs.AuthCodeGenerator,
		TokenGenerator:         configs.TokenGenerator,
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
		x.ErrorHandler(ctx, http.StatusBadRequest, err, errDesc)
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
		x.ErrorHandler(ctx, http.StatusBadRequest, errors.New(core.Err_invalid_request), errors.New("code chanllenge is required"))
		return
	}

	// client provided pkce chanllenge
	codeChanllengeMethod := string(ctx.FormValue(core.Form_CodeChallengeMethod))
	if codeChanllengeMethod == "" {
		codeChanllengeMethod = core.Pkce_Plain
	} else if codeChanllengeMethod != core.Pkce_Plain && codeChanllengeMethod != core.Pkce_S256 {
		x.ErrorHandler(ctx, http.StatusBadRequest, errors.New(core.Err_invalid_request), errors.New("transform algorithm not supported"))
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
	username := core.GetCookieValue(ctx, "Username")
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
		nil,
	)
	if err != nil {
		x.ErrorHandler(ctx, http.StatusBadRequest, errors.New(core.Err_server_error), err)
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
}

// ErrorHandler handle error
func (x *DefaultAuthServer) ErrorHandler(ctx *fasthttp.RequestCtx, statusCode int, err, errDesc error) {
	if errDesc == nil {
		errDesc = err
	}

	log.Warn(errDesc.Error())
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType(core.ContentType_Json)
	ctx.Response.Header.Add(core.Header_CacheControl, core.Header_CacheControl_Value)
	ctx.Response.Header.Add(core.Header_Pragma, core.Header_Pragma_Value)

	ctx.WriteString(fmt.Sprintf(core.Format_Error, err.Error(), errDesc.Error()))
}

func (x *DefaultAuthServer) relativeRedirectHandler(ctx *fasthttp.RequestCtx, relativeLocation string) {
	ctx.Response.Header.Add("Location", relativeLocation)
	ctx.Response.SetStatusCode(fasthttp.StatusFound)
}
