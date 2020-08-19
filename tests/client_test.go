package tests

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func Test(t *testing.T) {
	http.DefaultClient.Transport = &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://localhost:8888")
		},
	}

	config := &oauth2.Config{
		ClientID:     "test",
		ClientSecret: "password",
		Endpoint: oauth2.Endpoint{
			TokenURL:  "https://dp.dreamvat.com/connect/token",
			AuthURL:   "https://dp.dreamvat.com/connect/authorize",
			AuthStyle: 1,
		},
		RedirectURL: "https://www.test.com/signin-oauth",
	}

	var err error
	context := context.Background()
	token := &oauth2.Token{
		AccessToken:  "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2RpLmRyZWFtdmF0LmNvbSIsImVtYWlsIjoibHVraXlhQGx1a2l5YS5jb20iLCJleHAiOjE1OTc4NTM5NjYsImlhdCI6MTU5Nzg1Mzk2MSwiaXNzIjoiaHR0cHM6Ly9kcC5kcmVhbXZhdC5jb20iLCJsZXZlbCI6IjUiLCJuYW1lIjoiTHVraXlhIiwibmJmIjoxNTk3ODUzOTYxLCJyb2xlIjoiNCIsInN0YXR1cyI6IjEiLCJzdWIiOiIzY2I5NTQ5OTEwMDRiMDEifQ.Kah_zs4I9ZC04MuItwkQi26XEWUPPLXTU9rq-MoQzkvmD4aADHDunp1zVi4ngkHrB--mRGlM-xrtQ8M5eQraQ5bck-s2RmgJzvPIbOLH2TaQFyT5Slgk_PUSfGshu6zH8YBaS3kvlc04zhzTTB0CGAzzF-wskvaeEAGRchRvrirFWwepzdBrqb3bf4GStygHT-nsFmC0sTKWMFJTPFaraGo0vzFNhxkJcIbPLN2dIaSIC7y23l7P-8-HxjOYJSC1g82xeXVsNg6TxNMAtyZDki4ykenUYR5aLZYS3y0EWFxCuffiTTy9iYV5Mvpsrqv4GCA824fOsECJcsOM5bKFIQ",
		RefreshToken: "RQVsrhkvL-avon1PvLox07BBXP0eYnhonC-eGx1S3nNBw9SssjF6oQq6K9G07fS1YQdMSYke1gGjxkoM0uBu_Q",
		Expiry:       time.Now().Add(time.Second * -5),
		TokenType:    "Bearer",
	}
	ts := config.TokenSource(context, token)
	newToken, err := ts.Token()
	assert.NoError(t, err)
	if newToken.AccessToken != token.AccessToken {
		// save
	}

	client := oauth2.NewClient(context, ts)
	_, err = client.Get("https://di.dreamvat.com/posts/new")
	assert.NoError(t, err)
	_, err = client.Get("https://di.dreamvat.com/posts/new")
	assert.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = client.Get("https://di.dreamvat.com/posts/new")
	assert.NoError(t, err)
}
