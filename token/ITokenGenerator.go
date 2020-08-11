package token

import (
	"crypto/rsa"

	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/model"
	"github.com/dgrijalva/jwt-go"
	"github.com/syncfuture/go/u"
	"github.com/valyala/fasthttp"
)

type ITokenGenerator interface {
	GenerateAccessToken(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) (string, error)
	GenerateRefreshToken() string
}

func NewDefaultTokenGenerator(privateKey *rsa.PrivateKey, signingAlgorithm jwt.SigningMethod, claimsGenerator ITokenClaimsGenerator) ITokenGenerator {
	return &DefaultTokenGenerator{
		PrivateKey:       privateKey,
		SigningAlgorithm: signingAlgorithm,
		ClaimsGenerator:  claimsGenerator,
	}
}

type DefaultTokenGenerator struct {
	SigningAlgorithm jwt.SigningMethod
	PrivateKey       *rsa.PrivateKey
	ClaimsGenerator  ITokenClaimsGenerator
}

func (x *DefaultTokenGenerator) GenerateAccessToken(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) (string, error) {
	claims := x.ClaimsGenerator.Generate(ctx, grantType, client, scopes, username)
	token := jwt.NewWithClaims(x.SigningAlgorithm, claims)
	// token.Header["kid"] = ""
	// token.Header["x5t"] = ""

	signedAccessToken, err := token.SignedString(x.PrivateKey)
	if u.LogError(err) {
		return "", err
	}

	return signedAccessToken, nil
}

func (x *DefaultTokenGenerator) GenerateRefreshToken() string {
	return core.Random64String()
}
