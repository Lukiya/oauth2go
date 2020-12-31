package model

type IClient interface {
	GetID() string
	GetSecret() string
	GetAccessTokenExpireSeconds() int32
	GetRefreshTokenExpireSeconds() int32
	GetGrants() []string
	GetScopes() []string
	GetRedirectUris() []string
}
