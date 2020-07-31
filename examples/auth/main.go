//go:generate go get -u github.com/valyala/quicktemplate/qtc
//go:generate qtc -dir=views
package main

import (
	"net/url"

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
	claimsGenerator := NewClaimsGenerator()

	authServerOptions := &oauth2go.AuthServerOptions{
		PkceRequired:      true,
		ClientStore:       clientStore,
		TokenStore:        tokenStore,
		PrivateKey:        privateKey,
		ClaimsGenerator:   claimsGenerator,
		AuthorizeEndpoint: "/connect/authorize",
		TokenEndpoint:     "/connect/token",
		LoginEndpoint:     "/account/login",
	}
	authServer := oauth2go.NewDefaultAuthServer(authServerOptions)

	webServer := server.NewWebServer()
	webServer.Get(authServerOptions.AuthorizeEndpoint, authServer.AuthorizeRequestHandler)
	webServer.Post(authServerOptions.TokenEndpoint, authServer.TokenRequestHandler)
	webServer.Get("/", func(ctx *fasthttp.RequestCtx) { writePage(ctx, new(views.IndexPage)) })
	webServer.Get(authServerOptions.LoginEndpoint, func(ctx *fasthttp.RequestCtx) {
		username := core.GetCookieValue(ctx, authServerOptions.AuthCookieName)
		log.Info(username)

		returnURL := string(ctx.FormValue(core.Form_ReturnUrl))
		view := &views.LoginPage{
			ReturnURL: url.QueryEscape(returnURL),
		}
		writePage(ctx, view)
	})
	webServer.Post("/account/login", func(ctx *fasthttp.RequestCtx) {

		username := string(ctx.FormValue("Username"))
		// password := string(ctx.FormValue("Password"))
		returnURL := string(ctx.FormValue(core.Form_ReturnUrl))

		core.SetCookieValue(ctx, authServerOptions.AuthCookieName, username)

		core.Redirect(ctx, returnURL)
		// writePage(ctx, new(views.LoginPage))
	})
	webServer.Get("/account/logout", func(ctx *fasthttp.RequestCtx) {})
	webServer.ServeFiles(fasthttp.FSHandler("./wwwroot", 0))

	listenAddr := ":6001"
	log.Infof("listen on %s", listenAddr)
	fasthttp.ListenAndServe(listenAddr, webServer.Serve)
}

func writePage(ctx *fasthttp.RequestCtx, view views.Page) {
	ctx.SetContentType(core.ContentType_Html)
	views.WritePageTemplate(ctx, view)
}
