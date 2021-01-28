package rsa

import (
	"encoding/base64"

	"github.com/Lukiya/oauth2go/security"
	ss "github.com/syncfuture/go/ssecurity"
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

func (x *RSASecretEncryptor) EncryptStringToString(input string) string {
	r, err := x.encryptor.EncryptString(input)
	if u.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) EncryptBytesToString(input []byte) string {
	r, err := x.encryptor.Encrypt(input)
	if u.LogError(err) {
		return base64.StdEncoding.EncodeToString(input)
	}

	return base64.StdEncoding.EncodeToString(r)
}

func (x *RSASecretEncryptor) EncryptBytesToBytes(input []byte) []byte {
	r, err := x.encryptor.Encrypt(input)
	if u.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) DecryptStringToString(input string) string {
	r, err := x.encryptor.DecryptString(input)
	if u.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) DecryptBytesToBytes(input []byte) []byte {
	r, err := x.encryptor.Decrypt(input)
	if u.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) DecryptStringToBytes(input string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(input)
	if u.LogError(err) {
		return []byte(input)
	}

	r, err := x.encryptor.Decrypt(bytes)
	if u.LogError(err) {
		return []byte(input)
	}

	return r
}
