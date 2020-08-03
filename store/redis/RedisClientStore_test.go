package redis

import (
	"testing"

	"github.com/Lukiya/oauth2go/security/rsa"
	"github.com/stretchr/testify/assert"
	"github.com/syncfuture/go/config"
	"github.com/syncfuture/go/sredis"
)

func TestRedisClientStore_GetClient(t *testing.T) {
	var redisConfig *sredis.RedisConfig
	configProvider := config.NewJsonConfigProvider()
	configProvider.GetStruct("Redis", &redisConfig)
	secretEncryptor := rsa.NewRSASecretEncryptor("../../examples/cert/test.key")
	clientStore := NewRedisClientStore("CLIENTS", secretEncryptor, redisConfig)

	client := clientStore.GetClient("test")
	assert.NotNil(t, client)
}
