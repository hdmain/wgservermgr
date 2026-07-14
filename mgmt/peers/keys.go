package peers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

func GenerateKeyPair() (KeyPair, error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return KeyPair{}, fmt.Errorf("generate private key: %w", err)
	}
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return KeyPair{
		PrivateKey: hex.EncodeToString(privateKey[:]),
		PublicKey:  hex.EncodeToString(publicKey[:]),
	}, nil
}

func PublicKeyFromPrivate(privateKeyHex string) (string, error) {
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	if len(privateKey) != 32 {
		return "", fmt.Errorf("invalid private key length")
	}

	var pub, priv [32]byte
	copy(priv[:], privateKey)
	curve25519.ScalarBaseMult(&pub, &priv)
	return hex.EncodeToString(pub[:]), nil
}

func KeyHexToBase64(hexKey string) (string, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("decode key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
