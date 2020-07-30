package security

import (
	"github.com/Lukiya/oauth2go/core"
)

type IPkceValidator interface {
	Verify(codeVerifier, codeChanllenge, codeChanllengeMethod string) bool
}
type DefaultPkceValidator struct{}

func (x *DefaultPkceValidator) Verify(codeVerifier, codeChanllenge, codeChanllengeMethod string) bool {
	r := false

	if codeChanllengeMethod == core.Pkce_Plain {
		r = codeVerifier == codeChanllenge
	} else if codeChanllengeMethod == core.Pkce_S256 {
		r = codeChanllenge == core.ToSHA256Base64URL(codeVerifier)
	}

	// not suppor other methods
	return r
}
