package oauth2go

import (
	"context"
	"net/http"
	"time"

	"github.com/syncfuture/go/u"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type ClientCredential struct {
	Config      *clientcredentials.Config
	AccessToken *oauth2.Token
}

func (x *ClientCredential) Token() (r *oauth2.Token, err error) {
	if x.AccessToken == nil || time.Now().UTC().After(x.AccessToken.Expiry) {
		// 如果没有令牌或者令牌已过期，请求新令牌
		x.AccessToken, err = x.Config.Token(context.Background())
		if u.LogError(err) {
			return
		}
	}

	r = x.AccessToken

	return
}

func (x *ClientCredential) Client(context context.Context) *http.Client {
	tokenSource := oauth2.ReuseTokenSource(x.AccessToken, x)
	return oauth2.NewClient(context, tokenSource)
}
