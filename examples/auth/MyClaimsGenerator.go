package main

import (
	"strings"
	"time"

	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/token"
	"github.com/dgrijalva/jwt-go"
	"github.com/valyala/fasthttp"
)

func NewClaimsGenerator() token.ITokenClaimsGenerator {
	return &MyClaimsGenerator{}
}

type MyClaimsGenerator struct{}

func (x *MyClaimsGenerator) Generate(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) *jwt.MapClaims {
	utcNow := time.Now().UTC()
	exp := utcNow.Add(time.Duration(client.GetAccessTokenExpireSeconds()) * time.Second).Unix()

	r := &jwt.MapClaims{
		"name": username,
		"iss":  "https://p.ecp.com",
		"aud":  strings.Join(scopes, core.Seperator_Scope),
		"exp":  exp,
		"iat":  utcNow.Unix(),
		"nbf":  utcNow.Unix(),
	}

	return r
}
