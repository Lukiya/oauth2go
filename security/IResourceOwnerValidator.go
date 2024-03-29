package security

type IResourceOwnerValidator interface {
	Verify(username, password string) (bool, error)
}

func NewDefaultResourceOwnerValidator() IResourceOwnerValidator {
	return new(DefaultResourceOwnerValidator)
}

type DefaultResourceOwnerValidator struct{}

// Verify This default validator always return false,
// please implement your own validator
func (x *DefaultResourceOwnerValidator) Verify(username, password string) (bool, error) {
	return false, nil
}
