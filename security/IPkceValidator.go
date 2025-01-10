package security

import (
	"github.com/Lukiya/oauth2go/core"
	"github.com/syncfuture/go/slog"
)

type IPkceValidator interface {
	Verify(codeVerifier, codeChallenge, codeChallengeMethod string) bool
}

func NewDefaultPkceValidator() IPkceValidator {
	return &DefaultPkceValidator{}
}

type DefaultPkceValidator struct{}

func (x *DefaultPkceValidator) Verify(codeVerifier, codeChallenge, codeChallengeMethod string) bool {
	// check code_verifier length
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		slog.Warn("code_verifier length is invalid")
		return false
	}

	r := false

	// check code_challenge_method
	if codeChallengeMethod == core.Pkce_Plain {
		r = codeVerifier == codeChallenge
	} else if codeChallengeMethod == core.Pkce_S256 {
		r = codeChallenge == core.ToSHA256Base64URL(codeVerifier)
	}

	// not suppor other methods
	slog.Warnf("Unsupported code_challenge_method: %s", codeChallengeMethod)
	return r
}
