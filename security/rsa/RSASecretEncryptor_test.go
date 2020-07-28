package rsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRSASecretEncryptor(t *testing.T) {
	a := NewRSASecretEncryptor("../../examples/cert/test.key")

	raw := "xxxxxx"

	encrypted := a.EncryptString(raw)
	assert.NotEmpty(t, encrypted)
	t.Log(encrypted)

	decrypted := a.DecryptString(encrypted)
	assert.Equal(t, raw, decrypted)
}
