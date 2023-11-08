package grpcjwt

import (
	"context"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
	"testing"
)

func Test_defaultTokenExtractor(t *testing.T) {

	type args struct {
		setHeader     string
		extractHeader string
		token         string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok", args{"authorization", "authorization", "Bearer 123"}, "Bearer 123", false},
		{"bad header", args{"authorization", "bad", "Bearer 123"}, "", true},
		{"token missing", args{"authorization", "authorization", ""}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			md := metadata.Pairs(tt.args.setHeader, tt.args.token)
			ctx = metadata.NewIncomingContext(ctx, md)
			fn := TokenExtractorFromHeader(tt.args.extractHeader)
			s, err := fn(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("defaultTokenExtractor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, s)
		})
	}
}
