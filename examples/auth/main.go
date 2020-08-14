//go:generate go get -u github.com/valyala/quicktemplate/qtc
//go:generate qtc -dir=views
package main

import (
	"crypto/rand"
	"net/url"
	"strconv"
	"time"

	"github.com/Lukiya/oauth2go"
	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/examples/auth/views"
	"github.com/Lukiya/oauth2go/security/rsa"
	"github.com/Lukiya/oauth2go/server"
	"github.com/Lukiya/oauth2go/store/redis"
	"github.com/gorilla/securecookie"
	"github.com/syncfuture/go/config"
	"github.com/syncfuture/go/rsautil"
	log "github.com/syncfuture/go/slog"
	"github.com/syncfuture/go/sredis"
	"github.com/syncfuture/go/u"
	"github.com/valyala/fasthttp"
)

func main() {
	cp := config.NewJsonConfigProvider()
	log.Init(cp)
	var redisConfig *sredis.RedisConfig
	cp.GetStruct("Redis", &redisConfig)

	var authServerOptions *oauth2go.AuthServerOptions
	cp.GetStruct("OAuth", &authServerOptions)
	if authServerOptions == nil {
		authServerOptions = &oauth2go.AuthServerOptions{
			PkceRequired: true,
		}
	}
	hashKey := make([]byte, 32)
	blockKey := make([]byte, 32)
	rand.Read(hashKey)
	rand.Read(blockKey)
	authServerOptions.CookieManager = securecookie.New(hashKey, blockKey)
	secretEncryptor := rsa.NewRSASecretEncryptor("../cert/test.key")
	authServerOptions.ClientStore = redis.NewRedisClientStore("CLIENTS", secretEncryptor, redisConfig)
	authServerOptions.TokenStore = redis.NewRedisTokenStore("rt:", secretEncryptor, redisConfig)
	var err error
	authServerOptions.PrivateKey, err = rsautil.ReadPrivateKeyFromFile("../cert/test.key")
	u.LogFaltal(err)
	authServerOptions.ClaimsGenerator = newClaimsGenerator()
	authServerOptions.ResourceOwnerValidator = newResourceOwnerValidator()
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
				authServer.SetCookieValue(ctx, authServerOptions.AuthCookieName, username, 24*time.Hour*14)
			} else {
				authServer.SetCookieValue(ctx, authServerOptions.AuthCookieName, username, 0)
			}
			core.Redirect(ctx, returnURL)
			return
		}

		writePage(ctx, new(views.LoginPage))
	})
	webServer.Get(authServerOptions.LogoutEndpoint, authServer.LogoutRequestHandler)
	webServer.ServeFiles(fasthttp.FSHandler("./wwwroot", 0))

	listenAddr := cp.GetString("ListenAddr")
	log.Infof("listen on %s", listenAddr)
	fasthttp.ListenAndServe(listenAddr, webServer.Serve)
}

func writePage(ctx *fasthttp.RequestCtx, view views.Page) {
	ctx.SetContentType(core.ContentType_Html)
	views.WritePageTemplate(ctx, view)
}
