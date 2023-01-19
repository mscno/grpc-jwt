package grpcjwt

import (
	"bytes"
	"context"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"path"
)

// ExtractRequestParametersIntoCtx extracts the request parameters into the context.
func ExtractRequestParametersIntoCtx() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx = extractRequestParams(ctx, req, info)
		return handler(ctx, req)
	}
}

// extractRequestParams extracts the request parameters from the context and request.
func extractRequestParams(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	var requestCtx RequestCtx

	reqBytes := GetRawJSON(req)
	var byteSlice []byte
	if reqBytes != nil {
		byteSlice = reqBytes.Bytes()
	}

	method := path.Base(info.FullMethod)
	service := path.Dir(info.FullMethod)[1:]
	reqString := string(byteSlice)
	if reqString == "{}" {
		reqString = ""
	}

	requestCtx.Payload = reqString
	requestCtx.Method = method
	requestCtx.Service = service

	// Checks if auth has already been parsed by grpc-gateway
	if xForwardedFor := md.Get("x-forwarded-for"); len(xForwardedFor) != 0 {
		requestCtx.Ip = xForwardedFor[0]
	}

	if xRequestId := md.Get("x-request-id"); len(xRequestId) != 0 {
		requestCtx.RequestId = xRequestId[0]
	}

	if traceParent := md.Get("traceparent"); len(traceParent) != 0 {
		requestCtx.TraceParent = traceParent[0]

	}

	if xUserAgent := md.Get("grpcgateway-user-agent"); len(xUserAgent) != 0 {
		requestCtx.UserAgent = xUserAgent[0]
	} else if xUserAgent := md.Get("user-agent"); len(xUserAgent) != 0 {
		requestCtx.UserAgent = xUserAgent[0]
	} else {
		requestCtx.UserAgent = "unknown user agent"
	}

	if xGoogleClient := md.Get("x-google-api-client"); len(xGoogleClient) != 0 {
		requestCtx.UserAgent = xGoogleClient[0]
	}

	return newRequestContext(ctx, &requestCtx)
}

type RequestCtx struct {
	Method      string
	Service     string
	Payload     string
	RequestId   string
	TraceParent string
	UserAgent   string
	Ip          string
}

type requestCtxKey struct{}

// newRequestContext creates a new context with peer information attached.
func newRequestContext(ctx context.Context, p *RequestCtx) context.Context {
	return context.WithValue(ctx, requestCtxKey{}, p)
}

// RequestFromContext returns the peer information in ctx if it exists.
func RequestFromContext(ctx context.Context) (p *RequestCtx, ok bool) {
	p, ok = ctx.Value(requestCtxKey{}).(*RequestCtx)
	return
}

// GetRawJSON converts a Protobuf message to JSON bytes if less than MaxSize.
func GetRawJSON(i interface{}) *bytes.Buffer {
	if pb, ok := i.(proto.Message); ok {
		b := &bytes.Buffer{}
		if err := Marshaller.Marshal(b, pb); err == nil && b.Len() < MAX_SIZE {
			return b
		}
	}
	return nil
}

var Marshaller = &jsonpb.Marshaler{}

const MAX_SIZE = 2048000
