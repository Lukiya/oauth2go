package redis

import (
	"testing"

	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/security/rsa"
	"github.com/stretchr/testify/assert"
	"github.com/syncfuture/go/config"
	"github.com/syncfuture/go/sredis"
)

func TestRedisTokenStore(t *testing.T) {
	var redisConfig *sredis.RedisConfig
	configProvider := config.NewJsonConfigProvider()
	configProvider.GetStruct("Redis", &redisConfig)
	secretEncryptor := rsa.NewRSASecretEncryptor("../../examples/cert/test.key")
	_tokenStore := NewRedisTokenStore("rt:", secretEncryptor, redisConfig)

	a := &model.TokenInfo{
		ClientID: "test",
	}
	refreshToken := "abcdefg"
	_tokenStore.SaveRefreshToken(
		refreshToken,
		a,
		30,
	)
	b := _tokenStore.GetAndRemoveTokenInfo(refreshToken)

	assert.Equal(t, a.ClientID, b.ClientID)
	t.Log(b.ClientID)
}
