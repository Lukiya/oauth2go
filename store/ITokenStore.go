package store

import (
	"github.com/Lukiya/oauth2go/model"
)

type ITokenStore interface {
	RemoveRefreshToken(refreshToken string)
	SaveRefreshToken(refreshToken string, requestInfo *model.TokenInfo, expireSeconds int32)
	GetTokenInfo(refreshToken string) *model.TokenInfo
}
