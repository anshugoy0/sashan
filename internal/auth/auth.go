package auth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

const PRIVATE_KEY = "/home/anshugoy/.ssh/sashankey"

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
		return signed_token, fmt.Errorf("unable to generate signature: %v", err)
	}

	return signed_token, err
}
