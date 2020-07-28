package rsa

import (
	"github.com/Lukiya/oauth2go/security"
	ss "github.com/syncfuture/go/security"
	"github.com/syncfuture/go/u"
)

type RSASecretEncryptor struct {
	encryptor *ss.RSAEncryptor
}

func NewRSASecretEncryptor(certPath string) security.ISecretEncryptor {
	rsaEncryptor, err := ss.CreateRSAEncryptorFromFile(certPath)
	u.LogFaltal(err)

	return &RSASecretEncryptor{
		encryptor: rsaEncryptor,
	}
}

func (x *RSASecretEncryptor) EncryptString(input string) string {
	r, err := x.encryptor.EncryptString(input)
	if u.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) EncryptBytes(input []byte) []byte {
	r, err := x.encryptor.Encrypt(input)
	if u.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) DecryptString(input string) string {
	r, err := x.encryptor.DecryptString(input)
	if u.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) DecryptBytes(input []byte) []byte {
	r, err := x.encryptor.Decrypt(input)
	if u.LogError(err) {
		return input
	}

	return r
}
