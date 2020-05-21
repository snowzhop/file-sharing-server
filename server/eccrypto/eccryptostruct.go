package eccrypto

import (
	"crypto/cipher"
	"crypto/ecdsa"
)

const (
	// CommonPubKeyLength is a raw key length (04<X-Coordinate(32 bytes)><Y-Coordinate(32 bytes)>)
	CommonPubKeyLength = 66
	// NonceSize is a length of nonce slice in bytes
	NonceSize = 12
	// CipherKeyLength is a cipher key length in bytes
	CipherKeyLength = 32
)

// ECcrypto represents struct for Elliptic-Curve encryption
type ECcrypto struct {
	gcm     cipher.AEAD
	keyPair *ecdsa.PrivateKey
	nonce   []byte
	shared  [CipherKeyLength]byte
}
