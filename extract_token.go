package grpcjwt

import (
	"context"
	"google.golang.org/grpc/metadata"
)

const defaultMetadataHeader = "authorization"

var defaultExtractorFn = defaultTokenExtractor(defaultMetadataHeader)

func defaultTokenExtractor(header string) ExtractorFunc {
	return func(ctx context.Context) (string, error) {
		var token string
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return token, ErrMissingKey
		}
		authMetaData := md.Get(header)
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
}
