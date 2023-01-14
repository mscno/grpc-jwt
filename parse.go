package grpcjwt

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"strings"
)

type TokenParserFunc func(token string) (*jwt.Token, error)

func (svc *JWTValidator) parseToken(token string) (*jwt.Token, error) {
	fn := func(kid string) (*rsa.PublicKey, error) {
		rsaMap, err := svc.getKeyset(svc.config.JwksUrl)
		if err != nil {
			return nil, errors.Wrap(ErrJwksLoadError, err.Error())
		}
		rsaPubKey, found := rsaMap[kid]
		if !found {
			return nil, ErrPublicKeyNotFound
		}
		return rsaPubKey, nil
	}
	return parseToken(svc.config.Algorithm, jwt.MapClaims{"iss": svc.config.Issuer, "aud": jwt.ClaimStrings{svc.config.Audience}}, token, fn)
}

type RsaFunc func(kid string) (*rsa.PublicKey, error)

func parseToken(algo jwt.SigningMethod, claims jwt.Claims, tokenString string, rsaFunc RsaFunc) (*jwt.Token, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		signingKeyID, ok := token.Header["kid"].(string)
		if !ok || signingKeyID == "" {
			return nil, ErrMissingKidInHeader
		}
		return rsaFunc(signingKeyID)
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc, jwt.WithValidMethods([]string{algo.Alg()}))
	if err != nil {
		if err, ok := err.(*jwt.ValidationError); ok {
			switch {
			case err.Is(jwt.ErrTokenExpired):
				return nil, ErrTokenExpired
			case err.Is(jwt.ErrTokenMalformed):
				return nil, ErrTokenMalformed
			case err.Is(jwt.ErrTokenNotValidYet):
				return nil, ErrTokenNotValidYet
			case err.Is(jwt.ErrTokenUsedBeforeIssued):
				return nil, ErrTokenUsedBeforeIssued
			case err.Is(jwt.ErrTokenSignatureInvalid):
				if strings.Contains(err.Error(), "signing method") {
					return nil, ErrBadAlgorithm
				}
				return nil, ErrSignatureInvalid
			}
		}
		if strings.HasSuffix(err.Error(), ErrJwksLoadError.Error()) {
			return nil, errors.Wrap(ErrJwksLoadError, strings.TrimSuffix(err.Error(), ": "+ErrJwksLoadError.Error()))
		}
		if strings.HasSuffix(err.Error(), ErrPublicKeyNotFound.Error()) {
			return nil, errors.Wrap(ErrPublicKeyNotFound, strings.TrimSuffix(err.Error(), ": "+ErrPublicKeyNotFound.Error()))
		}
		return nil, errors.Wrap(ErrInternal, err.Error())
	}

	return token, nil
}
