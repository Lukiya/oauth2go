package redis

import (
	"testing"

	"github.com/Lukiya/oauth2go/security/rsa"
	"github.com/stretchr/testify/assert"
	config "github.com/syncfuture/go/sconfig"
	"github.com/syncfuture/go/sredis"
)

func TestRedisClientStore_GetClient(t *testing.T) {
	var redisConfig *sredis.RedisConfig
	configProvider := config.NewJsonConfigProvider()
	configProvider.GetStruct("Redis", &redisConfig)
	secretEncryptor := rsa.NewRSASecretEncryptor(`D:\Git\syncfuture\armos\go\pass\cert\private.key`)
	clientStore := NewRedisClientStore("hub:CLIENTS", secretEncryptor, redisConfig)

	client := clientStore.GetClient("amsadmin")
	assert.NotNil(t, client)
}
