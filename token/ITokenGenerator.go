package token

import (
	"crypto/rsa"

	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/model"
	"github.com/pascaldekloe/jwt"
	"github.com/syncfuture/go/u"
	"github.com/valyala/fasthttp"
)

type ITokenGenerator interface {
	GenerateAccessToken(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) (string, error)
	GenerateRefreshToken() string
}

func NewDefaultTokenGenerator(privateKey *rsa.PrivateKey, signingAlgorithm string, claimsGenerator ITokenClaimsGenerator) ITokenGenerator {
	return &DefaultTokenGenerator{
		PrivateKey:       privateKey,
		SigningAlgorithm: signingAlgorithm,
		ClaimsGenerator:  claimsGenerator,
	}
}

type DefaultTokenGenerator struct {
	SigningAlgorithm string
	PrivateKey       *rsa.PrivateKey
	ClaimsGenerator  ITokenClaimsGenerator
}

func (x *DefaultTokenGenerator) GenerateAccessToken(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) (string, error) {
	claims := new(jwt.Claims)
	claims.KeyID = core.GenerateID()
	// claims.Set = *x.ClaimsGenerator.Generate(ctx, grantType, client, scopes, username)
	claims.Set = *x.ClaimsGenerator.Generate(grantType, client, scopes, username)
	if subValue, ok := claims.Set["sub"]; ok {
		if sub, b := subValue.(string); b {
			claims.Subject = sub
		}
	}

	token, err := claims.RSASign(x.SigningAlgorithm, x.PrivateKey)
	return u.BytesToStr(token), err
}

func (x *DefaultTokenGenerator) GenerateRefreshToken() string {
	return core.Random64String()
}
