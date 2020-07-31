package token

import (
	"encoding/base64"

	"crypto/rand"
)

type IAuthCodeGenerator interface {
	Generate() string
}

func NewDefaultAuthCodeGenerator() IAuthCodeGenerator {
	return &DefaultAuthCodeGenerator{}
}

type DefaultAuthCodeGenerator struct{}

func (x *DefaultAuthCodeGenerator) Generate() string {
	randomNumber := make([]byte, 64)
	rand.Read(randomNumber)

	return base64.RawURLEncoding.EncodeToString(randomNumber)
}
