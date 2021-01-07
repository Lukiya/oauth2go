package oauth2go

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/security"
	"github.com/Lukiya/oauth2go/store"
	"github.com/Lukiya/oauth2go/token"
	"github.com/gorilla/securecookie"
	"github.com/pascaldekloe/jwt"
	log "github.com/syncfuture/go/slog"
	"github.com/syncfuture/go/u"
	"github.com/valyala/fasthttp"
)

type (
	AuthServerOptions struct {
		AuthCookieName string
		// SurferCookieName       string
		AuthorizeEndpoint      string
		TokenEndpoint          string
		EndSessionEndpoint     string
		LoginEndpoint          string
		LogoutEndpoint         string
		PkceRequired           bool
		CookieManager          *securecookie.SecureCookie
		PrivateKey             *rsa.PrivateKey
		ClientStore            store.IClientStore
		TokenStore             store.ITokenStore
		AuthorizationCodeStore store.IAuthorizationCodeStore
		ClientValidator        security.IClientValidator
		PkceValidator          security.IPkceValidator
		ResourceOwnerValidator security.IResourceOwnerValidator
		AuthCodeGenerator      token.IAuthCodeGenerator
		TokenGenerator         token.ITokenGenerator
		ClaimsGenerator        token.ITokenClaimsGenerator
	}

	DefaultAuthServer struct {
		Options                *AuthServerOptions
		AuthCookieName         string
		AuthorizeEndpoint      string
		TokenEndpoint          string
		EndSessionEndpoint     string
		LoginEndpoint          string
		LogoutEndpoint         string
		PkceRequired           bool
		CookieManager          *securecookie.SecureCookie
		ClientStore            store.IClientStore
		TokenStore             store.ITokenStore
		AuthorizationCodeStore store.IAuthorizationCodeStore
		ClientValidator        security.IClientValidator
		PkceValidator          security.IPkceValidator
		ResourceOwnerValidator security.IResourceOwnerValidator
		AuthCodeGenerator      token.IAuthCodeGenerator
		TokenGenerator         token.ITokenGenerator
	}
)

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
	if options.CookieManager == nil {
		log.Fatal("CookieManager cannot be nil")
	}
	if options.AuthCookieName == "" {
		options.AuthCookieName = "go.auth"
	}
	// if options.SurferCookieName == "" {
	// 	options.SurferCookieName = "go.surfer"
	// }
	if options.AuthorizeEndpoint == "" {
		options.AuthorizeEndpoint = "/connect/authorize"
	}
	if options.TokenEndpoint == "" {
		options.TokenEndpoint = "/connect/token"
	}
	if options.EndSessionEndpoint == "" {
		options.EndSessionEndpoint = "/connect/endsession"
	}
	if options.LoginEndpoint == "" {
		options.LoginEndpoint = "/account/login"
	}
	if options.LogoutEndpoint == "" {
		options.LogoutEndpoint = "/account/logout"
	}

	if options.AuthorizationCodeStore == nil {
		options.AuthorizationCodeStore = store.NewDefaultAuthorizationCodeStore(180)
	}
	if options.ClientValidator == nil {
		options.ClientValidator = security.NewDefaultClientValidator(options.ClientStore)
	}
	if options.AuthCodeGenerator == nil {
		options.AuthCodeGenerator = token.NewDefaultAuthCodeGenerator()
	}
	if options.PkceValidator == nil {
		options.PkceValidator = security.NewDefaultPkceValidator()
	}
	if options.TokenGenerator == nil {
		options.TokenGenerator = token.NewDefaultTokenGenerator(
			options.PrivateKey,
			jwt.PS256,
			options.ClaimsGenerator,
		)
	}
	if options.ResourceOwnerValidator == nil {
		options.ResourceOwnerValidator = security.NewDefaultResourceOwnerValidator()
	}

	return &DefaultAuthServer{
		Options:                options,
		AuthCookieName:         options.AuthCookieName,
		AuthorizeEndpoint:      options.AuthorizeEndpoint,
		TokenEndpoint:          options.TokenEndpoint,
		LoginEndpoint:          options.LoginEndpoint,
		LogoutEndpoint:         options.LogoutEndpoint,
		PkceRequired:           options.PkceRequired,
		CookieManager:          options.CookieManager,
		ClientStore:            options.ClientStore,
		TokenStore:             options.TokenStore,
		AuthorizationCodeStore: options.AuthorizationCodeStore,
		ClientValidator:        options.ClientValidator,
		ResourceOwnerValidator: options.ResourceOwnerValidator,
		AuthCodeGenerator:      options.AuthCodeGenerator,
		TokenGenerator:         options.TokenGenerator,
		PkceValidator:          options.PkceValidator,
	}
}

// AuthorizeRequestHandler handle authorize request
func (x *DefaultAuthServer) AuthorizeRequestHandler(ctx *fasthttp.RequestCtx) {
	respType := string(ctx.FormValue(core.Form_ResponseType))
	clientID := string(ctx.FormValue(core.Form_ClientID))
	redirectURI := string(ctx.FormValue(core.Form_RedirectUri))
	scopesStr := string(ctx.FormValue(core.Form_Scope))
	state := string(ctx.FormValue(core.Form_State))
	// surferID := x.getSurferID(ctx)

	// verify client
	client, err, errDesc := x.ClientValidator.VerifyRespTypeRedirectURIScope(
		clientID,
		respType,
		redirectURI,
		scopesStr,
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	username := x.GetCookie(ctx, x.AuthCookieName)
	if username == "" {
		returnURL := url.QueryEscape(string(ctx.URI().RequestURI()))
		targetURL := fmt.Sprintf("%s?%s=%s", x.LoginEndpoint, core.Form_ReturnUrl, returnURL)
		core.Redirect(ctx, targetURL)
		return
	}

	switch respType {
	case core.ResponseType_Code:
		x.AuthorizationCodeRequestHandler(ctx, client, respType, scopesStr, redirectURI, state, username)
	case core.ResponseType_Token:
		x.ImplicitTokenRequestHandler(ctx, client, respType, scopesStr, redirectURI, state, username)
	}
}

// AuthorizationCodeRequestHandler handle authorize code request
func (x *DefaultAuthServer) AuthorizationCodeRequestHandler(ctx *fasthttp.RequestCtx, client model.IClient, respType, scopesStr, redirectURI, state, username string) {
	var code string
	// pkce check
	if !x.PkceRequired {
		// pkce not required, just issue code
		code = x.AuthCodeGenerator.Generate()
		x.AuthorizationCodeStore.Save(
			code,
			&model.TokenInfo{
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
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("code chanllenge is required")
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// client provided pkce chanllenge
	codeChanllengeMethod := string(ctx.FormValue(core.Form_CodeChallengeMethod))
	if codeChanllengeMethod == "" {
		codeChanllengeMethod = core.Pkce_Plain
	} else if codeChanllengeMethod != core.Pkce_Plain && codeChanllengeMethod != core.Pkce_S256 {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("transform algorithm not supported")
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// issue authorization code
	code = x.AuthCodeGenerator.Generate()
	x.AuthorizationCodeStore.Save(
		code,
		&model.TokenInfo{
			ClientID:             client.GetID(),
			Scopes:               scopesStr,
			RedirectUri:          redirectURI,
			Username:             username,
			CodeChanllenge:       codeChanllenge,
			CodeChanllengeMethod: codeChanllengeMethod,
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
func (x *DefaultAuthServer) ImplicitTokenRequestHandler(ctx *fasthttp.RequestCtx, client model.IClient, respType, scopesStr, redirectURI, state, username string) {
	// user already logged in, issue token
	token, err := x.TokenGenerator.GenerateAccessToken(
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
		token,
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
	if grantTypeStr == core.GrantType_AuthorizationCode || grantTypeStr == core.GrantType_RefreshToken {
		// auth code & refresh grant doesn't require post scopes
		client, err, errDesc = x.ClientValidator.VerifyCredentialGrantType(credentials, grantTypeStr)
	} else {
		// other scopes must post scopes
		client, err, errDesc = x.ClientValidator.VerifyCredentialGrantTypeScope(credentials, grantTypeStr, scopesStr)
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
		x.handleClientCredentialsTokenRequest(ctx, client, scopesStr)
	case core.GrantType_AuthorizationCode:
		x.handleAuthorizationCodeTokenRequest(ctx, client)
	case core.GrantType_ResourceOwner:
		x.handleResourceOwnerTokenRequest(ctx, client, scopesStr)
	case core.GrantType_RefreshToken:
		x.handleRefreshTokenRequest(ctx, client)
	default:
		log.Warn(core.Err_unsupported_grant_type + ":" + grantTypeStr)
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_unsupported_grant_type), nil)
	}
}

func (x *DefaultAuthServer) EndSessionRequestHandler(ctx *fasthttp.RequestCtx) {
	clientID := string(ctx.FormValue(core.Form_ClientID))
	redirectURI := string(ctx.FormValue(core.Form_RedirectUri))
	state := string(ctx.FormValue(core.Form_State))
	// verify client
	_, err, errDesc := x.ClientValidator.VerifyRedirectURI(
		clientID,
		redirectURI,
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// delete login cookie
	x.DelCookie(ctx, x.AuthCookieName)

	// redirect to client
	targetURL := fmt.Sprintf("%s?%s=%s",
		redirectURI,
		core.Form_State,
		url.QueryEscape(state),
	)
	core.Redirect(ctx, targetURL)
}

func (x *DefaultAuthServer) GetCookie(ctx *fasthttp.RequestCtx, name string) string {
	encryptedCookie := string(ctx.Request.Header.Cookie(name))
	if encryptedCookie == "" {
		return ""
	}

	var r string
	err := x.CookieManager.Decode(name, encryptedCookie, &r)

	if u.LogError(err) {
		return ""
	}

	return r
}

func (x *DefaultAuthServer) SetCookie(ctx *fasthttp.RequestCtx, key, value string, duration time.Duration) {
	if encryptedCookie, err := x.CookieManager.Encode(key, value); err == nil {
		authCookie := fasthttp.AcquireCookie()
		authCookie.SetKey(key)
		authCookie.SetValue(encryptedCookie)
		authCookie.SetSecure(true)
		authCookie.SetPath("/")
		authCookie.SetHTTPOnly(true)
		if duration > 0 {
			authCookie.SetExpire(time.Now().Add(duration))
		}
		ctx.Response.Header.SetCookie(authCookie)
		defer fasthttp.ReleaseCookie(authCookie)
	} else {
		u.LogError(err)
	}
}

func (x *DefaultAuthServer) DelCookie(ctx *fasthttp.RequestCtx, key string) {
	ctx.Response.Header.DelCookie(key)

	authCookie := fasthttp.AcquireCookie()
	authCookie.SetKey(key)
	authCookie.SetSecure(true)
	authCookie.SetPath("/")
	authCookie.SetHTTPOnly(true)
	authCookie.SetExpire(fasthttp.CookieExpireDelete)
	ctx.Response.Header.SetCookie(authCookie)
}

func (x *DefaultAuthServer) GetOptions() *AuthServerOptions {
	return x.Options
}

// handleClientCredentialsTokenRequest handle client credentials token request
func (x *DefaultAuthServer) handleClientCredentialsTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient, scopesStr string) {
	// issue token directly
	token, err := x.TokenGenerator.GenerateAccessToken(
		ctx,
		core.GrantType_Client,
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

// handleAuthorizationCodeTokenRequest handle authorization code token request
func (x *DefaultAuthServer) handleAuthorizationCodeTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient) {
	// exchange token by using auhorization code
	code := string(ctx.FormValue(core.Form_Code))
	clientID := string(ctx.FormValue(core.Form_ClientID))
	redirectUri := string(ctx.FormValue(core.Form_RedirectUri))

	tokenInfo := x.AuthorizationCodeStore.GetThenRemove(code)
	if tokenInfo == nil {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("invalid authorization code")
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	if client.GetID() != clientID || clientID != tokenInfo.ClientID {
		err := errors.New(core.Err_invalid_request)
		errDesc := fmt.Errorf("client id doesn't match, original: '%s', current: '%s'", tokenInfo.ClientID, client.GetID())
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	if redirectUri != tokenInfo.RedirectUri {
		err := errors.New(core.Err_invalid_request)
		errDesc := fmt.Errorf("redirect uri doesn't match, original: '%s', current: '%s'", tokenInfo.RedirectUri, redirectUri)
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// pkce check
	if !x.PkceRequired {
		// issue token
		x.issueTokenByRequestInfo(ctx, core.GrantType_AuthorizationCode, client, tokenInfo)
		return
	}

	codeVierifier := string(ctx.FormValue(core.Form_CodeVerifier))
	if codeVierifier == "" {
		// client didn't provide code verifier, write error
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("code verifier is missing")
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	if !x.PkceValidator.Verify(codeVierifier, tokenInfo.CodeChanllenge, tokenInfo.CodeChanllengeMethod) {
		err := errors.New(core.Err_invalid_grant)
		errDesc := errors.New("code verifier is invalid")
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	oldRefreshToken := string(ctx.FormValue(core.Form_RefreshToken))
	if oldRefreshToken != "" {
		// received old refresh token, revoke it
		x.TokenStore.RemoveRefreshToken(oldRefreshToken)
	}

	// issue token
	x.issueTokenByRequestInfo(ctx, core.GrantType_AuthorizationCode, client, tokenInfo)
}

// handleResourceOwnerTokenRequest handle resource owner token request
func (x *DefaultAuthServer) handleResourceOwnerTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient, scopesStr string) {
	// verify username & password
	username := string(ctx.FormValue(core.Form_Username))
	password := string(ctx.FormValue(core.Form_Password))
	success := x.ResourceOwnerValidator.Verify(username, password)
	if success {
		// pass, issue token
		x.issueTokenByRequestInfo(ctx, core.GrantType_AuthorizationCode, client, &model.TokenInfo{
			ClientID: client.GetID(),
			Scopes:   scopesStr,
			Username: username,
		})
	} else {
		err := errors.New(core.Err_invalid_grant)
		errDesc := errors.New("username password doesn't match")
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
	}
}

// handleRefreshTokenRequest handle refresh token request
func (x *DefaultAuthServer) handleRefreshTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient) {
	refreshToken := string(ctx.FormValue(core.Form_RefreshToken))
	if refreshToken == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("refresh token is missing")
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	var tokenInfo = x.TokenStore.GetTokenInfo(refreshToken)
	if tokenInfo == nil {
		err := errors.New(core.Err_invalid_grant)
		errDesc := errors.New("refresh token is invalid or expired or revoked")
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	if client.GetID() != tokenInfo.ClientID {
		err := errors.New(core.Err_invalid_request)
		errDesc := fmt.Errorf("client id doesn't match, original: '%s', current: '%s'", tokenInfo.ClientID, client.GetID())
		log.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// issue token
	x.issueTokenByRequestInfo(ctx, core.GrantType_RefreshToken, client, tokenInfo)
}

func (x *DefaultAuthServer) handleLogoutRequest(ctx *fasthttp.RequestCtx, statusCode int, err, errDesc error) {
	if errDesc == nil {
		errDesc = err
	}

	ctx.SetStatusCode(statusCode)
	ctx.SetContentType(core.ContentType_Json)
	ctx.Response.Header.Add(core.Header_CacheControl, core.Header_CacheControl_Value)
	ctx.Response.Header.Add(core.Header_Pragma, core.Header_Pragma_Value)

	ctx.WriteString(fmt.Sprintf(core.Format_Error, err.Error(), errDesc.Error()))
}

// issueTokenByRequestInfo issue access token and refresh token
func (x *DefaultAuthServer) issueTokenByRequestInfo(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, tokenInfo *model.TokenInfo) {
	// issue token
	token, err := x.TokenGenerator.GenerateAccessToken(
		ctx,
		grantType,
		client,
		strings.Split(tokenInfo.Scopes, core.Seperator_Scope),
		tokenInfo.Username,
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_server_error), err)
		return
	}

	allowRefresh := false
	for _, grant := range client.GetGrants() {
		if grant == core.GrantType_RefreshToken {
			allowRefresh = true
			break
		}
	}
	if allowRefresh {
		// allowed to use refresh token
		var refreshToken = x.TokenGenerator.GenerateRefreshToken()
		x.TokenStore.SaveRefreshToken(refreshToken, tokenInfo, client.GetRefreshTokenExpireSeconds())
		x.writeToken(ctx, token, tokenInfo.Scopes, client.GetAccessTokenExpireSeconds(), refreshToken)
	} else {
		// not allowed to use refresh token
		x.writeToken(ctx, token, tokenInfo.Scopes, client.GetAccessTokenExpireSeconds(), "")
	}
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

// // getSurferID get surfer id
// func (x *DefaultAuthServer) getSurferID(ctx *fasthttp.RequestCtx) (surferID string) {
// 	surferID = x.GetCookie(ctx, x.Options.SurferCookieName)
// 	if surferID == "" {
// 		surferID = core.GenerateID()
// 		x.SetCookie(ctx, x.Options.SurferCookieName, surferID, 8784*time.Hour)
// 	}
// 	return
// }
