package eccrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// GenerateKeyPair returns new generated public key and saves whole key pair
func (e *ECcrypto) GenerateKeyPair() (ecdsa.PublicKey, error) {
	var err error
	e.keyPair, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return e.keyPair.PublicKey, err
}

// CalculateSharedKey calculates a shared key, saves it and
// creates cipher.AEAD for further encoding
func (e *ECcrypto) CalculateSharedKey(x, y *big.Int) error {
	raw, _ := e.keyPair.PublicKey.ScalarMult(x, y, e.keyPair.D.Bytes())
	e.shared = sha256.Sum256(raw.Bytes())
	e.calculateNonce()

	block, err := aes.NewCipher(e.shared[:])
	if err != nil {
		return err
	}

	e.gcm, err = cipher.NewGCM(block)
	if err != nil {
		e.gcm = nil
		return err
	}

	return nil
}

func (e *ECcrypto) calculateNonce() {
	e.nonce = e.shared[:NonceSize]
}

// Shared returns shared key
func (e *ECcrypto) Shared() [CipherKeyLength]byte {
	return e.shared
}

// Encrypt checks GCM field and returns encrypted secret
func (e *ECcrypto) Encrypt(secret []byte) ([]byte, error) {
	if e.gcm == nil {
		return nil, fmt.Errorf("Encrypt: gcm not initialized (gcm == nil)")
	}

	return e.gcm.Seal(nil, e.nonce, secret, nil), nil
}

// Decrypt checks GCM field and returns decrypts cipherText or error
func (e *ECcrypto) Decrypt(cipherText []byte) ([]byte, error) {
	if e.gcm == nil {
		return nil, fmt.Errorf("Decrypt: gcm not initialized (gcm == nil)")
	}

	return e.gcm.Open(nil, e.nonce, cipherText, nil)
}

// UnpackKey unpacks raw key to standard form
func UnpackKey(rawPubKey []uint8) (*big.Int, *big.Int, error) {
	if len(rawPubKey) != CommonPubKeyLength {
		return nil, nil, fmt.Errorf("UnpackKey: wrong raw key length")
	} else if !(rawPubKey[0] == '0' && rawPubKey[1] == '4') {
		return nil, nil, fmt.Errorf("UnpackKey: it's non-complete key form")
	}

	tmpKey := rawPubKey[2:]

	xBig := new(big.Int)
	xBig.SetBytes(tmpKey[:len(tmpKey)/2])

	yBig := new(big.Int)
	yBig.SetBytes(tmpKey[len(tmpKey)/2:])

	return xBig, yBig, nil
}

// PackKey transforms key to raw form
func PackKey(x, y *big.Int) []uint8 {
	completeKey := append([]byte("04"), x.Bytes()...)
	completeKey = append(completeKey, y.Bytes()...)
	return completeKey
}
