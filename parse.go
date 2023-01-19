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
		switch {
		default:
			return nil, errors.Wrap(ErrJwksLoadError, err.Error())
		}
	}

	wrappedFn := svc.wrapKeyFuncWithCache(jwks.Keyfunc)
	return jwt.ParseWithClaims(token, jwt.MapClaims{"iss": svc.config.Issuer, "aud": jwt.ClaimStrings{svc.config.Audience}}, wrappedFn, jwt.WithValidMethods([]string{svc.config.Algorithm.Alg()}))
}

const jwksCacheKey = "jwks"

func (svc *JWTValidator) wrapKeyFuncWithCache(sourceFunc jwt.Keyfunc) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.Wrap(ErrMissingKidInHeader, "token header kid is not a string")
		}
		item := svc.cache.Get(kid)
		if item != nil {
			return item.Value(), nil
		}
		keySet, err := sourceFunc(token)
		if err != nil {
			return nil, err
		}
		svc.cache.Set(kid, keySet, ttlcache.DefaultTTL)
		return keySet, nil
	}
}
