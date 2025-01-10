package model

type IClient interface {
	GetID() string
	GetSecret() string
	GetAccessTokenExpireSeconds() int32
	GetRefreshTokenExpireSeconds() int32
	GetPermissionLevel() int64
	GetIsPublic() bool
	GetGrants() []string
	GetAudiences() []string
	GetScopes() []string
	GetRedirectUris() []string
}
