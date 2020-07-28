package oauth2go

import (
	"github.com/Lukiya/oauth2go/routing"
	"github.com/valyala/fasthttp"
)

type DefaultAuthServer struct {
	AuthCookieName string
	TokenExpires   int
	// Endpoints                    *ServerEndpoints
	// ClientStore                  client.IClientStore
	// GeneratingTokenClaimsHandler TokenClaimsGenerator
	Router routing.IRouter
}

func (x *DefaultAuthServer) TokenRequestHandler(ctx *fasthttp.RequestCtx) {

}

func (x *DefaultAuthServer) AuthorizeRequestHandler(ctx *fasthttp.RequestCtx) {

}
