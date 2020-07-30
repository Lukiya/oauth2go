package security

type IResourceOwnerValidator interface {
	Vertify(username, password string) bool
}
