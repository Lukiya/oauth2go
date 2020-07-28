package routing

import (
	"net/http"

	"github.com/valyala/fasthttp"
)

type IRouter interface {
	Get(path string, handler fasthttp.RequestHandler)
	Post(path string, handler fasthttp.RequestHandler)
	ServeFiles(handler fasthttp.RequestHandler)
	Serve(ctx *fasthttp.RequestCtx)
}

const (
	_get  = "GET"
	_post = "POST"
)

func New() IRouter {
	return &DefaultRouter{
		routingTable: make(map[string]map[string]fasthttp.RequestHandler),
	}
}

type DefaultRouter struct {
	routingTable map[string]map[string]fasthttp.RequestHandler
	fileHandler  fasthttp.RequestHandler
}

func (x *DefaultRouter) Get(path string, handler fasthttp.RequestHandler) {
	x.addSubRoutes(path, _get, handler)
}
func (x *DefaultRouter) Post(path string, handler fasthttp.RequestHandler) {
	x.addSubRoutes(path, _post, handler)
}

func (x *DefaultRouter) addSubRoutes(path, method string, handler fasthttp.RequestHandler) {
	if route := x.routingTable[path]; route != nil {
		route[method] = handler
	} else {
		x.routingTable[path] = make(map[string]fasthttp.RequestHandler)
		x.routingTable[path][method] = handler
	}
}

func (x *DefaultRouter) ServeFiles(handler fasthttp.RequestHandler) {
	x.fileHandler = handler
}

func (x *DefaultRouter) Serve(ctx *fasthttp.RequestCtx) {
	path := string(ctx.URI().Path()) // Todo: use pool
	if pathRoute, ok := x.routingTable[path]; ok {
		method := string(ctx.Method()) // Todo: use pool
		if handler, ok := pathRoute[method]; ok {
			handler(ctx)
		}
	} else if x.fileHandler != nil {
		x.fileHandler(ctx)
	} else {
		ctx.SetStatusCode(http.StatusNotFound)
	}
}
