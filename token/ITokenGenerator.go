package token

import (
	"crypto/rsa"

	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/model"
	"github.com/pascaldekloe/jwt"
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
	claims.Set = *x.ClaimsGenerator.Generate(ctx, grantType, client, scopes, username)

	token, err := claims.RSASign(x.SigningAlgorithm, x.PrivateKey)
	return string(token), err
}

func (x *DefaultTokenGenerator) GenerateRefreshToken() string {
	return core.Random64String()
}
