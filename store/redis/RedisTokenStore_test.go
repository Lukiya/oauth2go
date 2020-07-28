package redis

import (
	"testing"

	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/store"
	"github.com/stretchr/testify/assert"
)

var (
	_tokenStore store.ITokenStore
)

func init() {
	_tokenStore = NewRedisTokenStore("rt:", _secretEncryptor, _redisConfig)
}

func TestRedisTokenStore(t *testing.T) {
	a := &model.TokenRequestInfo{
		ClientID: "test",
	}
	refreshToken := "abcdefg"
	_tokenStore.SaveRefreshToken(
		refreshToken,
		a,
		30,
	)
	b := _tokenStore.GetTokenRequestInfo(refreshToken)

	assert.Equal(t, a.ClientID, b.ClientID)
	t.Log(b.ClientID)
}
