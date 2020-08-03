package token

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
)

var _byte64Pool = &sync.Pool{
	New: func() interface{} {
		mem := make([]byte, 64)
		return &mem
	},
}

func generate() string {
	randomNumber := _byte64Pool.Get().(*[]byte)
	rand.Read(*randomNumber)
	defer _byte64Pool.Put(randomNumber)

	return base64.RawURLEncoding.EncodeToString(*randomNumber)
}
