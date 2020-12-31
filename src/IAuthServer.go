package oauth2go

import (
	"time"

	"github.com/valyala/fasthttp"
)

type IAuthServer interface {
	TokenRequestHandler(ctx *fasthttp.RequestCtx)
	AuthorizeRequestHandler(ctx *fasthttp.RequestCtx)
	EndSessionRequestHandler(ctx *fasthttp.RequestCtx)
	GetOptions() *AuthServerOptions
	GetCookie(ctx *fasthttp.RequestCtx, name string) string
	SetCookie(ctx *fasthttp.RequestCtx, key, value string, duration time.Duration)
	DelCookie(ctx *fasthttp.RequestCtx, key string)
}
