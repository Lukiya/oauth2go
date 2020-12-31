package token

import (
	"github.com/Lukiya/oauth2go/model"
	"github.com/dgrijalva/jwt-go"
	"github.com/valyala/fasthttp"
)

type ITokenClaimsGenerator interface {
	Generate(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) *jwt.MapClaims
}
