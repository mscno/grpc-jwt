package grpcjwt

import (
	"crypto/md5"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"time"
)

type TokenParserFunc func(token string) (*jwt.Token, error)

func (svc *JWTValidator) parseToken(token string) (*jwt.Token, error) {

	var keyFunc jwt.Keyfunc
	if svc.config.JwksUrl != "" {
		jwks, err := keyfunc.Get(svc.config.JwksUrl, keyfunc.Options{RefreshInterval: time.Minute * 5})
		if err != nil {
			return nil, errors.Wrap(ErrJwksLoadError, err.Error())
		}
		keyFunc = jwks.Keyfunc
	} else {
		givenKeys := make(map[string]keyfunc.GivenKey)
		givenKey := keyfunc.NewGivenHMACCustomWithOptions(svc.config.JwtSecret, keyfunc.GivenKeyOptions{Algorithm: svc.config.Algorithm.Alg()})
		givenKeys[getKidFromPrivate2(svc.config.JwtSecret)] = givenKey
		jwks := keyfunc.NewGiven(givenKeys)
		keyFunc = jwks.Keyfunc
	}

	//if err != nil {
	//	return nil, errors.Wrap(ErrJwksLoadError, err.Error())
	//}

	//wrappedFn := wrapKeyFuncWithCache(svc.cache, jwks.Keyfunc)
	return jwt.ParseWithClaims(
		token,
		jwt.MapClaims{"iss": svc.config.Issuer, "aud": jwt.ClaimStrings{svc.config.Audience}},
		keyFunc,
		jwt.WithValidMethods([]string{svc.config.Algorithm.Alg()}),
	)
}

func getKidFromPrivate2(key []byte) string {
	signKeyBytePrint := md5.Sum(key)
	signKeyStringPrint := fmt.Sprintf("%x", signKeyBytePrint)
	return signKeyStringPrint
}

func wrapKeyFuncWithCache(cache *ttlcache.Cache[string, any], sourceFunc jwt.Keyfunc) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.Wrap(ErrMissingKidInHeader, "token header kid is not a string")
		}
		item := cache.Get(kid)
		if item != nil {
			return item.Value(), nil
		}
		keySet, err := sourceFunc(token)
		if err != nil {
			return nil, err
		}
		cache.Set(kid, keySet, ttlcache.DefaultTTL)
		return keySet, nil
	}
}
