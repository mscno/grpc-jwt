package grpcjwt

import (
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
)

type TokenParserFunc func(token string) (*jwt.Token, error)

func (svc *JWTValidator) parseToken(token string) (*jwt.Token, error) {
	jwks, err := keyfunc.Get(svc.config.JwksUrl, keyfunc.Options{})
	if err != nil {
		return nil, errors.Wrap(ErrJwksLoadError, err.Error())
	}

	wrappedFn := wrapKeyFuncWithCache(svc.cache, jwks.Keyfunc)
	return jwt.ParseWithClaims(token, jwt.MapClaims{"iss": svc.config.Issuer, "aud": jwt.ClaimStrings{svc.config.Audience}}, wrappedFn, jwt.WithValidMethods([]string{svc.config.Algorithm.Alg()}))
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
