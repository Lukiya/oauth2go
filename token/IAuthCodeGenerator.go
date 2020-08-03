package token

type IAuthCodeGenerator interface {
	Generate() string
}

func NewDefaultAuthCodeGenerator() IAuthCodeGenerator {
	return &DefaultAuthCodeGenerator{}
}

type DefaultAuthCodeGenerator struct{}

func (x *DefaultAuthCodeGenerator) Generate() string {
	return generate()
}
