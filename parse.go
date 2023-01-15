package grpcjwt

import (
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
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
	return jwt.ParseWithClaims(token, jwt.MapClaims{"iss": svc.config.Issuer, "aud": jwt.ClaimStrings{svc.config.Audience}}, jwks.Keyfunc, jwt.WithValidMethods([]string{svc.config.Algorithm.Alg()}))
}
