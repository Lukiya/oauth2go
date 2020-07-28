package redis

import (
	"github.com/Lukiya/oauth2go/security"
	"github.com/Lukiya/oauth2go/security/rsa"
	"github.com/syncfuture/go/config"
	"github.com/syncfuture/go/sredis"
)

var (
	_secretEncryptor security.ISecretEncryptor
	_redisConfig     *sredis.RedisConfig
)

func init() {
	configProvider := config.NewJsonConfigProvider()
	configProvider.GetStruct("Redis", &_redisConfig)
	_secretEncryptor = rsa.NewRSASecretEncryptor("../../examples/cert/test.key")
}
