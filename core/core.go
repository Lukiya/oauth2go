package core

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/gorilla/securecookie"
	"github.com/sony/sonyflake"
	"github.com/syncfuture/go/u"
	"github.com/valyala/fasthttp"
)

const (
	Header_Authorization          = "Authorization"
	Header_CacheControl           = "Cache-Control"
	Header_CacheControl_Value     = "no-store"
	Header_Pragma                 = "Pragma"
	Header_Pragma_Value           = "no-cache"
	ContentType_Json              = "application/json;charset=UTF-8"
	ContentType_Html              = "text/html;charset=utf-8"
	Claim_Role                    = "role"
	Claim_Name                    = "name"
	Claim_Audience                = "aud"
	Claim_Issuer                  = "iss"
	Form_GrantType                = "grant_type"
	Form_ClientID                 = "client_id"
	Form_ClientSecret             = "client_secret"
	Form_RedirectUri              = "redirect_uri"
	Form_ReturnUrl                = "returnUrl"
	Form_State                    = "state"
	Form_Scope                    = "scope"
	Form_Code                     = "code"
	Form_Username                 = "username"
	Form_Password                 = "password"
	Form_ResponseType             = "response_type"
	Form_AccessToken              = "access_token"
	Form_RefreshToken             = "refresh_token"
	Form_TokenType                = "token_type"
	Form_TokenTypeBearer          = "Bearer"
	Form_ExpiresIn                = "expires_in"
	Form_CodeChallenge            = "code_challenge"
	Form_CodeChallengeMethod      = "code_challenge_method"
	Form_CodeVerifier             = "code_verifier"
	ResponseType_Token            = "token"
	ResponseType_Code             = "code"
	GrantType_Client              = "client_credentials"
	GrantType_AuthorizationCode   = "authorization_code"
	GrantType_Implicit            = "implicit"
	GrantType_ResourceOwner       = "password"
	GrantType_RefreshToken        = "refresh_token"
	Format_Token1                 = "{\"" + Form_AccessToken + "\":\"%s\",\"" + Form_ExpiresIn + "\":\"%d\",\"" + Form_Scope + "\":\"%s\",\"" + Form_TokenType + "\":\"" + Form_TokenTypeBearer + "\"}"
	Format_Token2                 = "{\"" + Form_AccessToken + "\":\"%s\",\"" + Form_RefreshToken + "\":\"%s\",\"" + Form_ExpiresIn + "\":\"%d\",\"" + Form_Scope + "\":\"%s\",\"" + Form_TokenType + "\":\"" + Form_TokenTypeBearer + "\"}"
	Format_Error                  = "{\"error\":\"%s\", \"error_description\":\"%s\"}"
	Msg_Success                   = ""
	Err_invalid_request           = "invalid_request"
	Err_invalid_client            = "invalid_client"
	Err_invalid_grant             = "invalid_grant"
	Err_unauthorized_client       = "unauthorized_client"
	Err_unsupported_grant_type    = "unsupported_grant_type"
	Err_unsupported_response_type = "unsupported_response_type"
	Err_invalid_scope             = "invalid_scope"
	Err_access_denied             = "access_denied"
	Err_description               = "error_description"
	Err_uri                       = "error_uri"
	Err_server_error              = "server_error"
	Pkce_Plain                    = "plain"
	Pkce_S256                     = "S256"
	Config_OAuth_PkceRequired     = "OAuth:PkceRequired"
	Token_Access                  = "access_token"
	Token_Refresh                 = "refresh_token"
	Token_ExpiresAt               = "expires_at"
	UtcTimesamp                   = "yyyy-MM-ddTHH:mm:ss.0000000+00:00"
	Seperator_Scope               = " "
	Seperators_Auth               = ":"
)

var (
	_idGenerator  *sonyflake.Sonyflake
	_secureCookie *securecookie.SecureCookie
)

func init() {
	hashKey := []byte("JGQUQERAY5xPNVkliVMgGpVjLmjk2VDFAcP2gTI70Dw=")
	blockKey := []byte("6MHdT1pG22lXjFcZzobwlQ==")
	_secureCookie = securecookie.New(hashKey, blockKey)
	_idGenerator = sonyflake.NewSonyflake(sonyflake.Settings{})
}

func ToSHA256Base64URL(in string) string {
	h := sha256.New()
	h.Write([]byte(in))
	r := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(r)
}

// func MakeURL(rawurl string, queries *map[string]string) *url.URL {
// 	r, err := url.Parse(rawurl)
// 	if u.LogError(err) {
// 		return nil
// 	}
// 	if queries != nil && len(*queries) > 0 {
// 		q := r.Query()
// 		for k, v := range *queries {
// 			q.Add(k, v)
// 		}
// 		r.RawQuery = q.Encode()
// 	}

// 	return r
// }

// func MakeURLStr(rawurl string, queries *map[string]string) string {
// 	r := MakeURL(rawurl, queries)
// 	if r != nil {
// 		return r.String()
// 	}
// 	return ""
// }

// GenerateID _
func GenerateID() string {
	a, _ := _idGenerator.NextID()
	return fmt.Sprintf("%x", a)
}

func Redirect(ctx *fasthttp.RequestCtx, url string) {
	ctx.Response.Header.Add("Location", url)
	ctx.Response.SetStatusCode(fasthttp.StatusFound)
}

func GetCookieValue(ctx *fasthttp.RequestCtx, key string) string {
	encryptedCookie := string(ctx.Request.Header.Cookie(key))
	if encryptedCookie == "" {
		return ""
	}

	var r string
	err := _secureCookie.Decode(key, encryptedCookie, &r)

	if u.LogError(err) {
		return ""
	}

	return r
}

func SetCookieValue(ctx *fasthttp.RequestCtx, key, value string) {
	if encryptedCookie, err := _secureCookie.Encode(key, value); err == nil {
		authCookie := fasthttp.AcquireCookie()
		authCookie.SetKey(key)
		authCookie.SetValue(encryptedCookie)
		authCookie.SetSecure(true)
		authCookie.SetPath("/")
		authCookie.SetHTTPOnly(true)
		ctx.Response.Header.SetCookie(authCookie)
	} else {
		u.LogError(err)
	}
}
