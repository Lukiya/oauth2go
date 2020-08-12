package oauth2go

import (
	"time"

	"github.com/valyala/fasthttp"
)

type IAuthServer interface {
	TokenRequestHandler(ctx *fasthttp.RequestCtx)
	AuthorizeRequestHandler(ctx *fasthttp.RequestCtx)
	GetCookieValue(ctx *fasthttp.RequestCtx, name string) string
	SetCookieValue(ctx *fasthttp.RequestCtx, key, value string, duration time.Duration)
}
