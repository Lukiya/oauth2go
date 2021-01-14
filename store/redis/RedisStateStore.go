package redis

import (
	"time"

	"github.com/Lukiya/oauth2go/security"
	"github.com/Lukiya/oauth2go/store"
	redis "github.com/go-redis/redis/v7"
	"github.com/syncfuture/go/sredis"
	"github.com/syncfuture/go/u"
)

type RedisStateStore struct {
	Prefix          string
	SecretEncryptor security.ISecretEncryptor
	RedisClient     redis.UniversalClient
}

func NewRedisStateStore(prefix string, secretEncryptor security.ISecretEncryptor, config *sredis.RedisConfig) store.ITokenStore {
	return &RedisTokenStore{
		Prefix:          prefix,
		SecretEncryptor: secretEncryptor,
		RedisClient:     sredis.NewClient(config),
	}
}

func (x *RedisStateStore) Save(key, value string, expireSeconds int) {
	err := x.RedisClient.Set(x.Prefix+key, value, time.Duration(expireSeconds)*time.Second).Err()
	u.LogError(err)
}
func (x *RedisStateStore) GetThenRemove(key string) (r string) {
	key = x.Prefix + key
	r = x.RedisClient.Get(key).String()
	if r != "" {
		err := x.RedisClient.Del(key).Err()
		u.LogError(err)
	}
	return
}
