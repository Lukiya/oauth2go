package server

import (
	"github.com/valyala/fasthttp"
)

type IWebServer interface {
	Get(path string, handler fasthttp.RequestHandler)
	Post(path string, handler fasthttp.RequestHandler)
	ServeFiles(handler fasthttp.RequestHandler)
	Serve(ctx *fasthttp.RequestCtx)
}
