package redis

import (
	"encoding/json"

	"github.com/Lukiya/oauth2go/model"
	"github.com/Lukiya/oauth2go/security"
	"github.com/Lukiya/oauth2go/store"
	redis "github.com/go-redis/redis/v7"
	log "github.com/syncfuture/go/slog"
	"github.com/syncfuture/go/sredis"
	"github.com/syncfuture/go/u"
)

type RedisClientStore struct {
	Key             string
	SecretEncryptor security.ISecretEncryptor
	RedisClient     redis.UniversalClient
}

func NewRedisClientStore(key string, secretEncryptor security.ISecretEncryptor, config *sredis.RedisConfig) store.IClientStore {
	return &RedisClientStore{
		Key:             key,
		SecretEncryptor: secretEncryptor,
		RedisClient:     sredis.NewClient(config),
	}
}

func (x *RedisClientStore) GetClient(clientID string) model.IClient {
	jsonBytes, err := x.RedisClient.HGet(x.Key, clientID).Bytes()
	if err != nil {
		if err.Error() == "redis: nil" {
			log.Warnf("client id: '%s' doesn't exist.", clientID)
			return nil
		}
		log.Error(err)
		return nil
	}

	var client *model.Client
	err = json.Unmarshal(jsonBytes, &client)
	if u.LogError(err) {
		return nil
	}

	if u.IsBase64String(client.Secret) {
		client.Secret = x.SecretEncryptor.DecryptStringToString(client.Secret)
	}

	return client
}

func (x *RedisClientStore) GetClients() map[string]model.IClient {
	maps, err := x.RedisClient.HGetAll(x.Key).Result()
	if u.LogError(err) {
		return nil
	}

	r := make(map[string]model.IClient, len(maps))

	for k, v := range maps {
		var client *model.Client
		err = json.Unmarshal([]byte(v), &client)
		if u.LogError(err) {
			return nil
		}
		client.Secret = x.SecretEncryptor.DecryptStringToString(client.Secret)
		r[k] = client
	}

	return r
}

func (x *RedisClientStore) Verify(clientID, clientSecret string) model.IClient {
	client := x.GetClient(clientID)
	if client == nil || client.GetSecret() != clientSecret {
		return nil
	}

	return client
}
