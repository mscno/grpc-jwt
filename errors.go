package grpcjwt

import (
	"github.com/pkg/errors"
)

type GrpcAuthErrors error

var (
	ErrInternal              GrpcAuthErrors = errors.New("internal error")
	ErrInvalidKey            GrpcAuthErrors = errors.New("bad jwt key")
	ErrMissingKey            GrpcAuthErrors = errors.New("authorization header missing")
	ErrTokenExpired          GrpcAuthErrors = errors.New("token is expired")
	ErrTokenUsedBeforeIssued GrpcAuthErrors = errors.New("token used before issued")
	ErrTokenNotValidYet      GrpcAuthErrors = errors.New("token is not valid yet")
	ErrTokenMalformed        GrpcAuthErrors = errors.New("token is malformed")
	ErrMissingKidInHeader    GrpcAuthErrors = errors.New("mising kid in header")
	ErrTokenInvalidAudience  GrpcAuthErrors = errors.New("bad audience")
	ErrTokenInvalidIssuer    GrpcAuthErrors = errors.New("bad issuer")
	ErrBadAlgorithm          GrpcAuthErrors = errors.New("bad algorithm")
	ErrJwksLoadError         GrpcAuthErrors = errors.New("jwks load error")
	ErrKIDNotFound           GrpcAuthErrors = errors.New("public key not found")
	ErrBadAuthScheme         GrpcAuthErrors = errors.New("bad auth scheme")
	ErrSignatureInvalid      GrpcAuthErrors = errors.New("signature is invalid")
)
