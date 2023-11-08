package grpcjwt

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_ClaimsDefault(t *testing.T) {

	var givenValidator = NewJWTValidator(Config{
		JwtSecret: []byte(privateTestKey),
		Algorithm: jwt.SigningMethodHS256,
		Audience:  "my-audience",
		Issuer:    "my-issuer",
	})

	outerCtx := ctx("Bearer " + getGivenToken("my-audience", "my-issuer", "my-user", time.Now().Add(time.Minute)))
	f := UnaryServerInterceptor(givenValidator)

	claimsChannel := make(chan jwt.MapClaims)
	defer close(claimsChannel)

	go func() {
		_, err := f(outerCtx, nil, nil, func(ctx context.Context, req interface{}) (interface{}, error) {
			claims, ok := GetClaims(ctx)
			if !ok {
				return nil, errors.New("claims not found")
			}
			claimsChannel <- claims
			return nil, nil
		})
		assert.NoError(t, err)
	}()

	claims := <-claimsChannel
	assert.NotNil(t, claims)
	assert.Equal(t, "my-user", claims["sub"])
	assert.Equal(t, "my-audience", claims["aud"])
	assert.Equal(t, "my-issuer", claims["iss"])
}

func Test_ClaimsCustom(t *testing.T) {

	var givenValidator = NewJWTValidator(Config{
		JwtSecret: []byte(privateTestKey),
		Algorithm: jwt.SigningMethodHS256,
		Audience:  "my-audience",
		Issuer:    "my-issuer",
		ClaimsHandler: func(ctx context.Context, claims jwt.MapClaims) context.Context {
			return context.WithValue(ctx, "user", claims["sub"])
		},
	})

	outerCtx := ctx("Bearer " + getGivenToken("my-audience", "my-issuer", "my-user", time.Now().Add(time.Minute)))
	f := UnaryServerInterceptor(givenValidator)

	userChannel := make(chan string)
	defer close(userChannel)

	go func() {
		_, err := f(outerCtx, nil, nil, func(ctx context.Context, req interface{}) (interface{}, error) {
			user, ok := ctx.Value("user").(string)
			if !ok {
				return nil, errors.New("claims not found")
			}
			userChannel <- user
			return nil, nil
		})
		assert.NoError(t, err)
	}()

	user := <-userChannel
	assert.Equal(t, "my-user", user)
}
