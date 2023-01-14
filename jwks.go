package grpcjwt

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jellydator/ttlcache/v3"
	"io"
	"net/http"
	"time"
)

const jwksCacheKey = "jwks"

type RSAKeySet map[string]*rsa.PublicKey

func (svc *JWTValidator) getKeyset(keyUrl string) (RSAKeySet, error) {
	item := svc.cache.Get(jwksCacheKey)
	if item != nil {
		return item.Value(), nil
	}
	keySet, err := getKeysetFromSource(keyUrl)
	if err != nil {
		return nil, err
	}
	svc.cache.Set(jwksCacheKey, keySet, ttlcache.DefaultTTL)
	return keySet, nil
}

func getKeysetFromSource(keyUrl string) (RSAKeySet, error) {
	payload, err := readBytesFromUrl(keyUrl)
	if err != nil {
		return nil, err
	}

	rsaMap, err := decodeRsaKeyMap(payload)
	if err != nil {
		return nil, err
	}

	return rsaMap, nil
}

func readBytesFromUrl(path string) ([]byte, error) {
	const jwksTimeout = 10 * time.Second
	var netClient = &http.Client{
		Timeout: jwksTimeout,
	}
	response, err := netClient.Get(path)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func decodeRsaKeyMap(jwksPayload []byte) (map[string]*rsa.PublicKey, error) {
	keys, err := unmarshalPublicKeys(jwksPayload)
	if err != nil {
		return nil, err
	}
	keyMap := map[string]*rsa.PublicKey{}
	for _, k := range keys {
		rsaPubKey, err := jwt.ParseRSAPublicKeyFromPEM(k.PublicKey)
		if err != nil {
			return nil, err
		}
		keyMap[k.Kid] = rsaPubKey
	}
	return keyMap, nil
}

func unmarshalPublicKeys(body []byte) ([]*publicKey, error) {
	jwtKeys := &jwtKeys{}
	err := json.Unmarshal(body, jwtKeys)
	if err != nil {
		return nil, err
	}

	keyStrings := make([]*publicKey, len(jwtKeys.Keys))
	for k, v := range jwtKeys.Keys {

		keyStrings[k] = &publicKey{
			Kid: v.Kid,
		}

		if len(v.X5c) != 0 {
			keyStrings[k].PublicKey = padKeyToByte(v.X5c[0])
		}
	}

	return keyStrings, nil
}

type jwtKey struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	Kid string   `json:"kid"`
	X5t string   `json:"x5t"`
}

type jwtKeys struct {
	Keys []jwtKey `json:"keys"`
}

type publicKey struct {
	Kid       string `json:"kid,omitempty"`
	PublicKey []byte `json:"public_key,omitempty""`
	N         string `json:"n"`
	E         string `json:"e"`
}

func padKeyToByte(key string) []byte {
	bytes := []byte("-----BEGIN CERTIFICATE-----\n" + key + "\n-----END CERTIFICATE-----")
	return bytes
}
