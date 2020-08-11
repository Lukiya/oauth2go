package token

import "github.com/Lukiya/oauth2go/core"

type IAuthCodeGenerator interface {
	Generate() string
}

func NewDefaultAuthCodeGenerator() IAuthCodeGenerator {
	return &DefaultAuthCodeGenerator{}
}

type DefaultAuthCodeGenerator struct{}

func (x *DefaultAuthCodeGenerator) Generate() string {
	return core.Random64String()
}
