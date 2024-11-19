package auth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

const PRIVATE_KEY = "/home/anshugoy/sashan/private-key.pem"
const PUBLIC_KEY = "/home/anshugoy/sashan/public-key.pem"

func GenerateJWT() (string, error) {
	var filePath string = PRIVATE_KEY
	token := jwt.NewWithClaims(jwt.SigningMethodES256,
		jwt.MapClaims{
			"iss": "sashan.org",
			"sub": "sashan",
		})

	keydata, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("can not read file: %v, err: %v", filePath, err)
	}

	block, _ := pem.Decode(keydata)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return "", fmt.Errorf("failed to parse pem")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("unable to parse the key block, err: %v", err)
	}

	signed_token, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("unable to generate signature: %v", err)
	}

	return signed_token, err
}

func ParsePublicKey() (any, error) {
	var filePath string = PUBLIC_KEY
	keydata, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("can not read file: %v, err: %v", filePath, err)
	}

	block, _ := pem.Decode(keydata)
	if block == nil {
		return nil, fmt.Errorf("failed to parse pem")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse the key block, err: %v", err)
	}
	return key, nil
}
