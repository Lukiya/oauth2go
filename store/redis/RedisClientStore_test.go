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

func TestRedisClientStore_GetClients(t *testing.T) {
	clients := _clientStore.GetClients()
	assert.NotEmpty(t, clients)
}

func TestRedisClientStore_Verify(t *testing.T) {
	client := _clientStore.Verify("test", "xxxxxx")
	assert.NotNil(t, client)
}
