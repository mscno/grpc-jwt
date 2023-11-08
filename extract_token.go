package grpcjwt

import (
	"context"
	"google.golang.org/grpc/metadata"
)

const defaultMetadataHeader = "authorization"

var defaultExtractorFn = TokenExtractorFromHeader(defaultMetadataHeader)

func TokenExtractorFromHeader(headers ...string) ExtractorFunc {
	return func(ctx context.Context) (string, error) {
		var token string
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return token, ErrMissingKey
		}
		for _, header := range headers {
			authMetaData := md.Get(header)
			if len(authMetaData) == 0 {
				continue
			} else {
				token = authMetaData[0]
				break
			}
		}
		if token == "" {
			return token, ErrMissingKey
		}
		return token, nil
	}
}
