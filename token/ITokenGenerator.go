package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"

	"github.com/Lukiya/oauth2go/model"
	"github.com/dgrijalva/jwt-go"
	"github.com/syncfuture/go/u"
	"github.com/valyala/fasthttp"
)

type ITokenGenerator interface {
	GenerateAccessToken(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string, claims *jwt.MapClaims) (string, error)
	GenerateRefreshToken() string
}

func NewDefaultTokenGenerator(privateKey *rsa.PrivateKey, signingAlgorithm jwt.SigningMethod) ITokenGenerator {
	return &DefaultTokenGenerator{
		PrivateKey:       privateKey,
		SigningAlgorithm: signingAlgorithm,
	}
}

type DefaultTokenGenerator struct {
	SigningAlgorithm jwt.SigningMethod
	PrivateKey       *rsa.PrivateKey
}

func (x *DefaultTokenGenerator) GenerateAccessToken(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string, claims *jwt.MapClaims) (string, error) {
	var token *jwt.Token
	if claims != nil {
		token = jwt.NewWithClaims(x.SigningAlgorithm, claims)
	} else {
		token = jwt.New(x.SigningAlgorithm)
	}

	signedAccessToken, err := token.SignedString(x.PrivateKey)
	if u.LogError(err) {
		return "", err
	}

	return signedAccessToken, nil
}

func (x *DefaultTokenGenerator) GenerateRefreshToken() string {
	randomNumber := make([]byte, 64)
	rand.Read(randomNumber)

	return base64.URLEncoding.EncodeToString(randomNumber)
}
