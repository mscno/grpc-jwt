package grpcjwt

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
)

type claimsKey struct {
}

func setClaimsInContext(ctx context.Context, claims jwt.MapClaims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

func GetClaims(ctx context.Context) (jwt.MapClaims, bool) {
	val, ok := ctx.Value(claimsKey{}).(jwt.MapClaims)
	return val, ok
}
