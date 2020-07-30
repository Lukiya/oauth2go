package redis

import (
	"testing"

	"github.com/Lukiya/oauth2go/store"
	"github.com/stretchr/testify/assert"
)

var (
	_clientStore store.IClientStore
)

func init() {
	_clientStore = NewRedisClientStore("CLIENTS", _secretEncryptor, _redisConfig)
}

func TestRedisClientStore_GetClient(t *testing.T) {
	client := _clientStore.GetClient("test")
	assert.NotNil(t, client)
}
