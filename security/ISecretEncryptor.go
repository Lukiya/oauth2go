package security

type ISecretEncryptor interface {
	EncryptStringToString(input string) string
	EncryptBytesToBytes(input []byte) []byte
	EncryptBytesToString(input []byte) string

	DecryptStringToString(input string) string
	DecryptBytesToBytes(input []byte) []byte
	DecryptStringToBytes(input string) []byte
}
