package redis

import (
	"encoding/json"
	"time"

	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/security"
	"github.com/Lukiya/oauth2go/store"
	redis "github.com/go-redis/redis/v7"
	"github.com/syncfuture/go/sredis"
	"github.com/syncfuture/go/u"
)

type RedisTokenStore struct {
	Prefix          string
	SecretEncryptor security.ISecretEncryptor
	RedisClient     redis.UniversalClient
}

func NewRedisTokenStore(prefix string, secretEncryptor security.ISecretEncryptor, config *sredis.RedisConfig) store.ITokenStore {
	return &RedisTokenStore{
		Prefix:          prefix,
		SecretEncryptor: secretEncryptor,
		RedisClient:     sredis.NewClient(config),
	}
}
func (x *RedisTokenStore) SaveRefreshToken(refreshToken string, requestInfo *model.TokenRequestInfo, expireSeconds int32) {
	// serialize to json
	bytes, err := json.Marshal(requestInfo)
	if u.LogError(err) {
		return
	}

	// encrypt
	bytes = x.SecretEncryptor.EncryptBytes(bytes)

	// save to redis
	x.RedisClient.Set(x.Prefix+refreshToken, bytes, time.Second*time.Duration(expireSeconds))
}
func (x *RedisTokenStore) GetTokenRequestInfo(refreshToken string) *model.TokenRequestInfo {
	key := x.Prefix + refreshToken

	// get from redis
	bytes, err := x.RedisClient.Get(key).Bytes()
	if u.LogError(err) {
		return nil
	}

	// decrypt & deserialize json
	bytes = x.SecretEncryptor.DecryptBytes(bytes)
	var info *model.TokenRequestInfo
	err = json.Unmarshal(bytes, &info)
	if u.LogError(err) {
		return nil
	}

	// delete used token
	err = x.RedisClient.Del(key).Err()
	u.LogError(err)

	return info
}
