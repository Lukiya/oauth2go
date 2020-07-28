package store

import (
	"github.com/Lukiya/oauth2go/model"
)

type IClientStore interface {
	GetClient(clientID string) model.IClient
	GetClients() map[string]model.IClient
	Verify(clientID, clientSecret string) model.IClient
}
