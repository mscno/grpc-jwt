package grpcjwt

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_handleError(t *testing.T) {
	type args struct {
		err           error
		setErrorCodes bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{"nil", args{nil, false}, nil},
		{"nil", args{nil, true}, nil},
		{"error", args{jwt.ErrInvalidKey, false}, jwt.ErrInvalidKey},
		{"error", args{fmt.Errorf("error"), true}, ErrInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := handleError(tt.args.err, tt.args.setErrorCodes)
			if tt.wantErr != nil {
				assert.ErrorContains(t, res, tt.wantErr.Error())
				return
			}
			assert.NoError(t, res)
		})
	}
}

func Test_setGrpcErrorCodes(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want error
	}{
		{"nil", args{nil}, nil},
		{"error", args{ErrTokenExpired}, ErrTokenExpired},
		{"error", args{ErrTokenMissingScope}, ErrTokenMissingScope},
		{"error", args{ErrTokenInvalidAudience}, ErrTokenInvalidAudience},
		{"error", args{ErrTokenInvalidIssuer}, ErrTokenInvalidIssuer},
		{"error", args{ErrSignatureInvalid}, ErrSignatureInvalid},
		{"error", args{ErrTokenMalformed}, ErrTokenMalformed},
		{"error", args{ErrBadAlgorithm}, ErrBadAlgorithm},
		{"error", args{ErrKIDNotFound}, ErrKIDNotFound},
		{"error", args{ErrTokenUsedBeforeIssued}, ErrTokenUsedBeforeIssued},
		{"error", args{ErrTokenNotValidYet}, ErrTokenNotValidYet},
		{"error", args{ErrBadAuthScheme}, ErrBadAuthScheme},
		{"error", args{ErrMissingKey}, ErrMissingKey},
		{"error", args{ErrJwksLoadError}, ErrJwksLoadError},
		{"error", args{fmt.Errorf("error")}, ErrInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := setGrpcErrorCodes(tt.args.err)
			if tt.want != nil {
				assert.ErrorContains(t, res, tt.want.Error())
				return
			}
			assert.NoError(t, res)
		})
	}
}
