package store

import (
	"time"

	"github.com/muesli/cache2go"
	"github.com/syncfuture/go/u"
)

const _clientStateKey = "ClientState"

type IClientStateStore interface {
	Save(clientID, requestID, state string)
	GetThenRemove(clientID, requestID string) string
}

func NewDefaultClientStateStore(durationSecondes int) IClientStateStore {
	cache := cache2go.Cache(_clientStateKey)

	return &DefaultClientStateStore{
		cache:    cache,
		duration: time.Second * time.Duration(durationSecondes),
	}
}

type DefaultClientStateStore struct {
	cache    *cache2go.CacheTable
	duration time.Duration
}

// Save client state to memory.
// This default in memory store doesn't encrypt state.
// Encryption is an option for security enhancement,
// you can implement your own store to do that.
func (x *DefaultClientStateStore) Save(clientID, requestID, state string) {
	key := clientID + ":" + requestID
	x.cache.Add(key, x.duration, state)
}

func (x *DefaultClientStateStore) GetThenRemove(clientID, requestID string) string {
	key := clientID + ":" + requestID
	cacheItem, err := x.cache.Delete(key)
	if err == cache2go.ErrKeyNotFound || u.LogError(err) {
		return ""
	}

	r := cacheItem.Data()

	return r.(string)
}
