package grpcjwt

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
)

type AuthFunc func(ctx context.Context) (context.Context, error)

// AuthFunc returns a new AuthFunc that can be used to authenticate a gRPC request. It is compatible with the grpc_auth middleware.
func (svc *JWTValidator) AuthFunc() AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		ctx, err := svc.validate(ctx)
		return ctx, handleError(err, svc.config.SetGrpcStatusCodes)
	}
}

func (svc *JWTValidator) validate(ctx context.Context) (context.Context, error) {
	// Get the method name from the context and check if we should skip the auth check
	methodName, _ := GetMethodName(ctx)
	if svc.config.Skip(ctx, methodName) {
		return ctx, nil
	}
	// Get raw token from grpc metadata
	tokenString, err := svc.config.Extractor(ctx)
	if err != nil {
		return nil, handleJwtError(err)
	}
	// Check auth scheme
	tokenString, err = checkScheme(svc.config.Scheme, tokenString)
	if err != nil {
		return nil, handleJwtError(err)
	}
	// Parse token
	token, err := svc.parseToken(tokenString)
	if err != nil {
		return nil, handleJwtError(err)
	}
	// Verify standard claims
	err = verifyStandardClaims(token, svc.config)
	if err != nil {
		return nil, handleJwtError(err)
	}
	// Set claims in context
	ctx = svc.config.ClaimsHandler(ctx, token.Claims.(jwt.MapClaims))
	return ctx, nil

}

// UnaryServerInterceptor is the main entry point for validating auth
func UnaryServerInterceptor(validator *JWTValidator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx, err := validator.AuthFunc()(ctx)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}
