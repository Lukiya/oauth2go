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
func (x *RedisTokenStore) SaveRefreshToken(refreshToken string, requestInfo *model.TokenInfo, expireSeconds int32) {
	// serialize to json
	bytes, err := json.Marshal(requestInfo)
	if u.LogError(err) {
		return
	}

	// encrypt
	encodedRefreshToken := x.SecretEncryptor.EncryptBytesToString(bytes)

	// save to redis
	err = x.RedisClient.Set(x.Prefix+refreshToken, encodedRefreshToken, time.Second*time.Duration(expireSeconds)).Err()
	u.LogError(err)
}
func (x *RedisTokenStore) RemoveRefreshToken(refreshToken string) {
	err := x.RedisClient.Del(x.Prefix + refreshToken).Err()
	u.LogError(err)
}
func (x *RedisTokenStore) GetAndRemoveTokenInfo(refreshToken string) *model.TokenInfo {
	key := x.Prefix + refreshToken

	// get from redis
	str, err := x.RedisClient.Get(key).Result()
	if u.LogError(err) {
		return nil
	}

	// decrypt & deserialize json
	bytes := x.SecretEncryptor.DecryptStringToBytes(str)
	var info *model.TokenInfo
	err = json.Unmarshal(bytes, &info)
	if u.LogError(err) {
		return nil
	}

	// delete used token
	err = x.RedisClient.Del(key).Err()
	u.LogError(err)

	return info
}
