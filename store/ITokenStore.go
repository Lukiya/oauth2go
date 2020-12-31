package store

import (
	"github.com/Lukiya/oauth2go/model"
)

type ITokenStore interface {
	SaveRefreshToken(refreshToken string, requestInfo *model.TokenInfo, expireSeconds int32)
	GetTokenRequestInfo(refreshToken string) *model.TokenInfo
}
