package grpcjwt

import (
	"crypto/md5"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type TokenParserFunc func(token string) (*jwt.Token, error)

func (svc *JWTValidator) parseToken(token string) (*jwt.Token, error) {
	var keyFunc jwt.Keyfunc
	if svc.config.JwksUrl != "" {
		jwks, err := keyfunc.Get(svc.config.JwksUrl, keyfunc.Options{RefreshInterval: time.Minute * 5})
		if err != nil {
			return nil, fmt.Errorf("%v: %w", err, ErrJwksLoadError)
		}
		keyFunc = jwks.Keyfunc
	} else {
		givenKeys := make(map[string]keyfunc.GivenKey)
		givenKey := keyfunc.NewGivenHMACCustomWithOptions(svc.config.JwtSecret, keyfunc.GivenKeyOptions{Algorithm: svc.config.Algorithm.Alg()})
		givenKeys[getKidFromPrivateKey(svc.config.JwtSecret)] = givenKey
		jwks := keyfunc.NewGiven(givenKeys)
		keyFunc = jwks.Keyfunc
	}

	return jwt.ParseWithClaims(
		token,
		jwt.MapClaims{"iss": svc.config.Issuer, "aud": jwt.ClaimStrings{svc.config.Audience}},
		keyFunc,
		jwt.WithValidMethods([]string{svc.config.Algorithm.Alg()}),
	)
}

func getKidFromPrivateKey(key []byte) string {
	signKeyBytePrint := md5.Sum(key)
	signKeyStringPrint := fmt.Sprintf("%x", signKeyBytePrint)
	return signKeyStringPrint
}
