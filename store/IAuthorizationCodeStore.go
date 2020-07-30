package store

import (
	"time"

	"github.com/Lukiya/oauth2go/model"
	"github.com/muesli/cache2go"
	"github.com/syncfuture/go/u"
)

type IAuthorizationCodeStore interface {
	Save(code string, requestInfo *model.TokenRequestInfo)
	GetThenRemove(code string) *model.TokenRequestInfo
}

func NewDefaultAuthorizationCodeStore(durationSecondes int) IAuthorizationCodeStore {
	cache := cache2go.Cache("AuthCode")

	return &DefaultAuthorizationCodeStore{
		cache:    cache,
		duration: time.Second * time.Duration(durationSecondes),
	}
}

type DefaultAuthorizationCodeStore struct {
	cache    *cache2go.CacheTable
	duration time.Duration
}

func (x *DefaultAuthorizationCodeStore) Save(code string, requestInfo *model.TokenRequestInfo) {
	x.cache.Add(code, x.duration, requestInfo)
}

func (x *DefaultAuthorizationCodeStore) GetThenRemove(code string) *model.TokenRequestInfo {
	cacheItem, err := x.cache.Delete(code)
	if err == cache2go.ErrKeyNotFound || u.LogError(err) {
		return nil
	}

	r := cacheItem.Data()

	return r.(*model.TokenRequestInfo)
}
