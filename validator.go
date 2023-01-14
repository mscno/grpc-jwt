package grpcjwt

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jellydator/ttlcache/v3"
	"time"
)

// Config holds the configuration for the JWTValidator
type Config struct {
	// JwksUrl is the url to the jwks endpoint
	JwksUrl string
	// Algorithm is the algorithm used to sign the token
	Algorithm jwt.SigningMethod
	// CacheTTL is the time to live for the jwks cache
	CacheTTL int64
	// Audience is the audience of the token
	Audience string
	// Issuer is the issuer of the token
	Issuer string
}

// JWTValidator is a validator for JWT tokens
type JWTValidator struct {
	cache  *ttlcache.Cache[string, map[string]*rsa.PublicKey]
	config Config
}

// NewJWTValidator Initializes the validator
func NewJWTValidator(cfg Config) *JWTValidator {
	cache := ttlcache.New[string, map[string]*rsa.PublicKey](
		ttlcache.WithTTL[string, map[string]*rsa.PublicKey](60 * time.Minute),
	)

	return &JWTValidator{
		cache:  cache,
		config: cfg,
	}
}
