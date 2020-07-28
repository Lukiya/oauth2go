package security

type ISecretEncryptor interface {
	EncryptString(input string) string
	DecryptString(input string) string

	EncryptBytes(input []byte) []byte
	DecryptBytes(input []byte) []byte
}
