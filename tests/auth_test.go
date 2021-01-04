package tests

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/Lukiya/oauth2go"
	"github.com/Lukiya/oauth2go/core"
	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/security"
	"github.com/Lukiya/oauth2go/security/rsa"
	"github.com/Lukiya/oauth2go/store/redis"
	"github.com/Lukiya/oauth2go/token"
	"github.com/gorilla/securecookie"
	"github.com/syncfuture/go/config"
	"github.com/syncfuture/go/rsautil"
	log "github.com/syncfuture/go/slog"
	"github.com/syncfuture/go/sredis"
	"github.com/syncfuture/go/u"
	"github.com/valyala/fasthttp"
)

func TestStarup(t *testing.T) {
	cp := config.NewJsonConfigProvider()
	log.Init(cp)
	var redisConfig *sredis.RedisConfig
	cp.GetStruct("Redis", &redisConfig)

	var authServerOptions *oauth2go.AuthServerOptions
	cp.GetStruct("OAuth", &authServerOptions)
	if authServerOptions == nil {
		authServerOptions = &oauth2go.AuthServerOptions{
			PkceRequired: true,
		}
	}
	hashKey := make([]byte, 32)
	blockKey := make([]byte, 32)
	rand.Read(hashKey)
	rand.Read(blockKey)
	authServerOptions.CookieManager = securecookie.New(hashKey, blockKey)
	secretEncryptor := rsa.NewRSASecretEncryptor("./cert/test.key")
	authServerOptions.ClientStore = redis.NewRedisClientStore("CLIENTS", secretEncryptor, redisConfig)
	authServerOptions.TokenStore = redis.NewRedisTokenStore("rt:", secretEncryptor, redisConfig)
	var err error
	authServerOptions.PrivateKey, err = rsautil.ReadPrivateKeyFromFile("./cert/test.key")
	u.LogFaltal(err)
	authServerOptions.ClaimsGenerator = newClaimsGenerator()
	authServerOptions.ResourceOwnerValidator = newResourceOwnerValidator()
	authServer := oauth2go.NewDefaultAuthServer(authServerOptions)
	t.Log(authServer)
}

func newClaimsGenerator() token.ITokenClaimsGenerator {
	return &MyClaimsGenerator{}
}

type MyClaimsGenerator struct{}

func (x *MyClaimsGenerator) Generate(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) *map[string]interface{} {
	utcNow := time.Now().UTC()
	exp := utcNow.Add(time.Duration(client.GetAccessTokenExpireSeconds()) * time.Second).Unix()

	r := &map[string]interface{}{
		"name": username,
		"iss":  "https://p.ecp.com",
		"aud":  strings.Join(scopes, core.Seperator_Scope),
		"exp":  exp,
		"iat":  utcNow.Unix(),
		"nbf":  utcNow.Unix(),
	}

	return r
}

func newResourceOwnerValidator() security.IResourceOwnerValidator {
	return &MyResourceOwnerValidator{}
}

type MyResourceOwnerValidator struct{}

func (x *MyResourceOwnerValidator) Verify(username, password string) bool {
	return username == password // just for testing
}
