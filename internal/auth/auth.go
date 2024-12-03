package auth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

const ENV_PRIVATE_KEY = "SA_PRIVATE_KEY"
const ENV_PUBLIC_KEY = "SA_PUBLIC_KEY"

func GenerateJWT(username string) (string, error) {
	var filePath string = os.Getenv(ENV_PRIVATE_KEY)
	token := jwt.NewWithClaims(jwt.SigningMethodES256,
		jwt.MapClaims{
			"iss":      "sashan.org",
			"sub":      "sashan",
			"username": username,
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
	var filePath string = os.Getenv(ENV_PUBLIC_KEY)
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
