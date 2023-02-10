package grpcjwt

import (
	"context"
	"google.golang.org/grpc"
)

type methodNameKey struct{}

// SetMethodNameInContext sets the method name in the context.
func SetMethodNameInContext() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx = context.WithValue(ctx, methodNameKey{}, info.FullMethod)
		return handler(ctx, req)
	}
}

func GetMethodName(ctx context.Context) (string, bool) {
	val, ok := ctx.Value(methodNameKey{}).(string)
	return val, ok
}
