package grpcjwt

import (
	"context"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"strings"
)

type AuthFunc func(ctx context.Context) (context.Context, error)

func (svc *JWTValidator) NewAuthFunc() AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		tokenString, err := extractTokenFromGrpcMetadata(ctx)
		if err != nil {
			return nil, handleError(err)
		}
		token, err := svc.parseToken(tokenString)
		if err != nil {
			return nil, handleError(err)
		}
		err = verifyStandardClaims(token, svc.config)
		if err != nil {
			return nil, handleError(err)
		}
		return ctx, nil
	}
}

// ParseAndValidateJWTAuthHeader is the main entry point for validating auth
func (svc *JWTValidator) ParseAndValidateJWTAuthHeader() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx, err := svc.NewAuthFunc()(ctx)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func verifyStandardClaims(user *jwt.Token, cfg Config) error {
	claims := user.Claims.(jwt.MapClaims)
	audience := claims.VerifyAudience(cfg.Audience, true)
	if !audience {
		return ErrTokenInvalidAudience
	}
	issuer := claims.VerifyIssuer(cfg.Issuer, true)
	if !issuer {
		return ErrTokenInvalidIssuer
	}
	return nil
}

var defaultExtractor = extractTokenFromGrpcMetadata

func extractTokenFromGrpcMetadata(ctx context.Context) (string, error) {
	var token string
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return token, ErrMissingKey
	}
	authMetaData := md.Get("Authorization")
	if len(authMetaData) == 0 {
		return token, ErrMissingKey
	} else {
		token = authMetaData[0]
	}
	if token == "" {
		return token, ErrMissingKey
	}
	return checkBearerToken(token)
}

func checkBearerToken(authHeader string) (string, error) {
	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return "", ErrBadAuthScheme
	}
	return parts[1], nil
}

func handleError(err error) error {
	if err, ok := err.(*jwt.ValidationError); ok {
		switch {
		case err.Is(jwt.ErrTokenExpired):
			return ErrTokenExpired
		case err.Is(jwt.ErrTokenMalformed):
			return ErrTokenMalformed
		case err.Is(jwt.ErrTokenNotValidYet):
			return ErrTokenNotValidYet
		case err.Is(jwt.ErrTokenUsedBeforeIssued):
			return ErrTokenUsedBeforeIssued
		case err.Is(keyfunc.ErrKIDNotFound):
			return ErrPublicKeyNotFound
		case err.Is(jwt.ErrTokenSignatureInvalid):
			if strings.Contains(err.Error(), "signing method") {
				return ErrBadAlgorithm
			}
			return ErrSignatureInvalid
		}
	}
	return err
}
