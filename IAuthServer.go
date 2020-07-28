package oauth2go

import "github.com/valyala/fasthttp"

type IAuthServer interface {
	TokenRequestHandler(ctx *fasthttp.RequestCtx)
	AuthorizeRequestHandler(ctx *fasthttp.RequestCtx)
}

func NewDefaultAuthServer() IAuthServer {
	return &DefaultAuthServer{}
}
