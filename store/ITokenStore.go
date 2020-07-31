package store

import (
	"github.com/Lukiya/oauth2go/model"
)

type ITokenStore interface {
	SaveRefreshToken(refreshToken string, requestInfo *model.TokenRequestInfo, expireSeconds int32)
	GetTokenRequestInfo(refreshToken string) *model.TokenRequestInfo
}
