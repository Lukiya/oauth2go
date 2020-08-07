//go:generate go get -u github.com/valyala/quicktemplate/qtc
//go:generate qtc -dir=views
package main

import (
	"net/url"
	"strconv"
	"time"

	"github.com/Lukiya/oauth2go"
	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/examples/auth/views"
	"github.com/Lukiya/oauth2go/security/rsa"
	"github.com/Lukiya/oauth2go/server"
	"github.com/Lukiya/oauth2go/store/redis"
	"github.com/syncfuture/go/config"
	"github.com/syncfuture/go/rsautil"
	log "github.com/syncfuture/go/slog"
	"github.com/syncfuture/go/sredis"
	"github.com/syncfuture/go/u"
	"github.com/valyala/fasthttp"
)

func main() {
	log.Init()
	cfp := config.NewJsonConfigProvider()
	var redisConfig *sredis.RedisConfig
	cfp.GetStruct("Redis", &redisConfig)

	secretEncryptor := rsa.NewRSASecretEncryptor("../cert/test.key")
	clientStore := redis.NewRedisClientStore("CLIENTS", secretEncryptor, redisConfig)
	tokenStore := redis.NewRedisTokenStore("rt:", secretEncryptor, redisConfig)
	privateKey, err := rsautil.ReadPrivateKeyFromFile("../cert/test.key")
	u.LogFaltal(err)
	claimsGenerator := newClaimsGenerator()

	resourceOwnerValidator := newResourceOwnerValidator()

	var authServerOptions *oauth2go.AuthServerOptions
	cfp.GetStruct("OAuth", &authServerOptions)
	if authServerOptions == nil {
		authServerOptions = &oauth2go.AuthServerOptions{
			PkceRequired: true,
		}
	}
	authServerOptions.ClientStore = clientStore
	authServerOptions.TokenStore = tokenStore
	authServerOptions.PrivateKey = privateKey
	authServerOptions.ClaimsGenerator = claimsGenerator
	authServerOptions.ResourceOwnerValidator = resourceOwnerValidator
	authServer := oauth2go.NewDefaultAuthServer(authServerOptions)

	webServer := server.NewWebServer()
	webServer.Get(authServerOptions.AuthorizeEndpoint, authServer.AuthorizeRequestHandler)
	webServer.Post(authServerOptions.TokenEndpoint, authServer.TokenRequestHandler)
	webServer.Get("/", func(ctx *fasthttp.RequestCtx) { writePage(ctx, new(views.IndexPage)) })
	webServer.Get(authServerOptions.LoginEndpoint, func(ctx *fasthttp.RequestCtx) {
		returnURL := string(ctx.FormValue(core.Form_ReturnUrl))
		view := &views.LoginPage{
			ReturnURL: url.QueryEscape(returnURL),
		}
		writePage(ctx, view)
	})
	webServer.Post(authServerOptions.LoginEndpoint, func(ctx *fasthttp.RequestCtx) {
		username := string(ctx.FormValue("Username"))
		password := string(ctx.FormValue("Password"))
		rememberLogin, _ := strconv.ParseBool(string(ctx.FormValue("RememberLogin")))
		returnURL := string(ctx.FormValue(core.Form_ReturnUrl))

		if username != password || rememberLogin { // just for testing
			if rememberLogin {
				// set login cookie
				core.SetCookieValue(ctx, authServerOptions.AuthCookieName, username, 24*time.Hour*14)
			} else {
				core.SetCookieValue(ctx, authServerOptions.AuthCookieName, username, 0)
			}
			core.Redirect(ctx, returnURL)
			return
		}

		writePage(ctx, new(views.LoginPage))
	})
	webServer.Get(authServerOptions.LogoutEndpoint, func(ctx *fasthttp.RequestCtx) {})
	webServer.ServeFiles(fasthttp.FSHandler("./wwwroot", 0))

	listenAddr := cfp.GetString("ListenAddr")
	log.Infof("listen on %s", listenAddr)
	fasthttp.ListenAndServe(listenAddr, webServer.Serve)
}

func writePage(ctx *fasthttp.RequestCtx, view views.Page) {
	ctx.SetContentType(core.ContentType_Html)
	views.WritePageTemplate(ctx, view)
}
