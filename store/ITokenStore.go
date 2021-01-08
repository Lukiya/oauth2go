package store

import (
	"github.com/Lukiya/oauth2go/model"
)

type ITokenStore interface {
	RemoveRefreshToken(refreshToken string)
	SaveRefreshToken(refreshToken string, requestInfo *model.TokenInfo, expireSeconds int32)
	GetAndRemoveTokenInfo(refreshToken string) *model.TokenInfo
}
