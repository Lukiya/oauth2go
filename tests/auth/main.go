//go:generate go get -u github.com/valyala/quicktemplate/qtc
//go:generate qtc -dir=./...
package main

import (
	"time"

	"github.com/Lukiya/oauth2go"
	oauth2core "github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/security"
	"github.com/Lukiya/oauth2go/security/rsa"
	"github.com/Lukiya/oauth2go/server"
	"github.com/Lukiya/oauth2go/store/redis"
	"github.com/Lukiya/oauth2go/token"
	"github.com/gorilla/securecookie"
	config "github.com/syncfuture/go/sconfig"
	log "github.com/syncfuture/go/slog"
	"github.com/syncfuture/go/sredis"
	rsautil "github.com/syncfuture/go/srsautil"
	"github.com/syncfuture/go/surl"
	"github.com/syncfuture/go/u"
	"github.com/valyala/fasthttp"
)

type _authServerOptions struct {
	oauth2go.AuthServerOptions
	PrivateKeyPath string
	HashKey        string
	BlockKey       string
	ListenAddr     string
}

var (
	_configProvider config.IConfigProvider
	_urlProvider    surl.IURLProvider
	_authServer     oauth2go.IAuthServer
	_options        *_authServerOptions
)

func newClaimsGenerator() token.ITokenClaimsGenerator {
	return &myClaimsGenerator{}
}

type myClaimsGenerator struct{}

func (x *myClaimsGenerator) Generate(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) *map[string]interface{} {
	utcNow := time.Now().UTC()
	exp := utcNow.Add(time.Duration(client.GetAccessTokenExpireSeconds()) * time.Second).Unix()

	r := map[string]interface{}{
		"name": username,
		"iss":  _urlProvider.RenderURLCache("{{URI 'pass'}}"),
		"exp":  exp,
		"iat":  utcNow.Unix(),
		"nbf":  utcNow.Unix(),
	}

	r["aud"] = []string{"testapi"}
	r["scope"] = []string{"testapi.user", "testapi.order"}

	if grantType == oauth2core.GrantType_Client {
		r["name"] = client.GetID()
		r["role"] = "1"
	} else {
		r["sub"] = "123456789"
		r["name"] = username
		r["email"] = "test@test.com"
		r["role"] = "4"
		r["level"] = "5"
		r["status"] = "1"
	}

	return &r
}

func newResourceOwnerValidator() security.IResourceOwnerValidator {
	return &myResourceOwnerValidator{}
}

type myResourceOwnerValidator struct{}

func (x *myResourceOwnerValidator) Verify(username, password string) bool {
	return username == password
}

func main() {
	_configProvider = config.NewJsonConfigProvider()
	log.Init(_configProvider)
	var redisConfig *sredis.RedisConfig
	_configProvider.GetStruct("Redis", &redisConfig)
	_urlProvider = surl.NewRedisURLProvider("t:URIS", redisConfig)

	_configProvider.GetStruct("AuthServer", &_options)
	if _options == nil {
		_options = new(_authServerOptions)
	}

	var err error
	_options.PrivateKey, err = rsautil.ReadPrivateKeyFromFile(_options.PrivateKeyPath)
	u.LogFaltal(err)
	secretEncryptor := rsa.NewRSASecretEncryptor(_options.PrivateKeyPath)
	_options.CookieManager = securecookie.New([]byte(_options.HashKey), []byte(_options.BlockKey))
	_options.ClientStore = redis.NewRedisClientStore("t:Clients", secretEncryptor, redisConfig)
	_options.TokenStore = redis.NewRedisTokenStore("rt:", secretEncryptor, redisConfig)
	_options.ClaimsGenerator = newClaimsGenerator()
	_options.ResourceOwnerValidator = newResourceOwnerValidator()
	_authServer = oauth2go.NewDefaultAuthServer(&_options.AuthServerOptions)

	webServer := server.NewWebServer()
	// authorize
	webServer.Get(_options.AuthorizeEndpoint, _authServer.AuthorizeRequestHandler)
	webServer.Post(_options.TokenEndpoint, _authServer.TokenRequestHandler)
	// end session
	webServer.Get(_options.EndSessionEndpoint, _authServer.EndSessionRequestHandler)
	webServer.Post(_options.EndSessionEndpoint, _authServer.ClearTokenRequestHandler)
	// home
	webServer.Get("/", homePageGet)
	// login
	webServer.Get(_options.LoginEndpoint, loginPageGet)
	webServer.Post(_options.LoginEndpoint, loginPagePost)
	// logout
	webServer.Get(_options.LogoutEndpoint, func(ctx *fasthttp.RequestCtx) {
		_authServer.DelCookie(ctx, _options.AuthCookieName)
		oauth2core.Redirect(ctx, "/")
	})
	// static files
	webServer.ServeFiles(fasthttp.FSHandler("./wwwroot", 0))

	log.Infof("listen on %s", _options.ListenAddr)
	fasthttp.ListenAndServe(_options.ListenAddr, webServer.Serve)
}
