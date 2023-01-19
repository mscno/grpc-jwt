package grpcjwt

import (
	"context"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strings"
)

type AuthFunc func(ctx context.Context) (context.Context, error)

func (svc *JWTValidator) NewAuthFunc() AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		// Get the method name from the context and check if we should skip the auth check
		methodName, _ := GetMethodName(ctx)
		if svc.config.Skip(ctx, methodName) {
			return ctx, nil
		}
		// Get raw token from grpc metadata
		tokenString, err := svc.config.Extractor(ctx)
		if err != nil {
			return nil, handleError(err)
		}
		// Check auth scheme
		tokenString, err = checkAuthScheme(svc.config.Scheme, tokenString)
		if err != nil {
			return nil, handleError(err)
		}
		// Parse token
		token, err := svc.parseToken(tokenString)
		if err != nil {
			return nil, handleError(err)
		}
		// Verify standard claims
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
			return ErrTokenInvalidAudience
		}
	}

	return nil
}

var defaultSkipFn = skipNone

func skipNone(ctx context.Context, fullMethodName string) bool {
	return false
}

var defaultExtractor = extractTokenFromGrpcMetadata

const defaultMetadataHeader = "authorization"

func extractTokenFromGrpcMetadata(ctx context.Context) (string, error) {
	var token string
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return token, ErrMissingKey
	}
	authMetaData := md.Get(defaultMetadataHeader)
	if len(authMetaData) == 0 {
		return token, ErrMissingKey
	} else {
		token = authMetaData[0]
	}
	if token == "" {
		return token, ErrMissingKey
	}
	return token, nil
}

func checkAuthScheme(scheme string, authHeader string) (string, error) {
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
			return ErrKIDNotFound
		case err.Is(jwt.ErrTokenSignatureInvalid):
			if strings.Contains(err.Error(), "signing method") {
				return ErrBadAlgorithm
			}
			return ErrSignatureInvalid
		}
	}
	return err
}

func setError(err error) error {
	switch err {
	case nil:
		return nil
	case ErrTokenExpired:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrTokenMalformed:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrTokenNotValidYet:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrTokenUsedBeforeIssued:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrKIDNotFound:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrBadAlgorithm:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrSignatureInvalid:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrTokenMalformed:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrTokenInvalidAudience:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrTokenInvalidIssuer:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrBadAuthScheme:
		return status.Error(codes.Unauthenticated, err.Error())
	case ErrMissingKey:
		return status.Error(codes.Unauthenticated, err.Error())
	default:
		return status.Error(codes.Unauthenticated, err.Error())
	}
}

func verifyScope(m jwt.MapClaims, scopeKey string, cmp []string, required bool) bool {
	scopes := extractStringSliceFromClaims(m, scopeKey)
	if len(scopes) == 0 {
		return !required
	}
	for _, s := range cmp {
		if !stringContains(scopes, s) {
			return false
		}
	}
	return required
}

func extractStringSliceFromClaims(m jwt.MapClaims, key string) []string {
	var stringSlice []string
	switch v := m[key].(type) {
	case string:
		stringSlice = append(stringSlice, v)
	case []string:
		stringSlice = v
	case []interface{}:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return nil
			}
			stringSlice = append(stringSlice, vs)
		}
	}
	return stringSlice
}

func stringContains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
