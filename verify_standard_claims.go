package grpcjwt

import (
	"github.com/golang-jwt/jwt/v4"
	"strings"
)

func verifyStandardClaims(user *jwt.Token, cfg Config) error {
	claims := user.Claims.(jwt.MapClaims)
	if cfg.Audience != "" {
		ok := claims.VerifyAudience(cfg.Audience, true)
		if !ok {
			return ErrTokenInvalidAudience
		}
	}

	if cfg.Issuer != "" {
		ok := claims.VerifyIssuer(cfg.Issuer, true)
		if !ok {
			return ErrTokenInvalidIssuer
		}
	}

	if len(cfg.Scope) > 0 {
		ok := verifyScope(claims, cfg.ScopeKey, cfg.Scope, true)
		if !ok {
			return ErrTokenMissingScope
		}
	}

	return nil
}

func verifyScope(m jwt.MapClaims, scopeKey string, cmp []string, required bool) bool {
	scopes := extractStringSliceFromClaims(m, scopeKey)
	for _, s := range cmp {
		if !stringSliceContains(scopes, s) {
			return false
		}
	}
	return required
}

func extractStringSliceFromClaims(m jwt.MapClaims, key string) []string {
	var stringSlice []string
	switch v := m[key].(type) {
	case string:
		stringSlice = append(stringSlice, strings.Split(v, " ")...)
	case []string:
		stringSlice = v
	case []interface{}:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				continue
			}
			stringSlice = append(stringSlice, vs)
		}
	}
	return stringSlice
}

func stringSliceContains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
