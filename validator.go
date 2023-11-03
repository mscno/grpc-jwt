package grpcjwt

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jellydator/ttlcache/v3"
)

// Config holds the configuration for the JWTValidator
type Config struct {
	// JwksUrl is the url to the jwks endpoint
	JwksUrl string
	// JwtSecret is the key used to sign the token
	JwtSecret []byte
	// Algorithm is the algorithm used to sign the token
	Algorithm jwt.SigningMethod
	// CacheTTL is the time to live for the jwks cache. It is measured in minutes. Defaults to 60 minutes.
	CacheTTL time.Duration
	// Audience is the audience of the token
	Audience string
	// Issuer is the issuer of the token
	Issuer string
	// Skip is a function to determine whether to skip the validation. It takes a context and a method name as params. If no function is provided, the validation will always be performed.
	Skip SkipFn
	// Extractor is a function to extract the token from the context. It takes a context as param. If no extractor is provided, the default extractor will be used (the default extractor uses the "Authorization" header).
	Extractor ExtractorFunc
	// Sets the auth schema of the Authorization header. Defaults to "Bearer".
	Scheme string
	// List of scopes that are required to access the service. If empty, no scope validation will be performed.
	Scope []string
	// Name of the claims field that contains the scopes. Defaults to "scope".
	ScopeKey string
	// If true, the validator will set the grpc status code to "PermissionDenied" if the scope validation fails. Defaults to false.
	SetGrpcStatusCodes bool
}

// SkipFn is a function to determine whether to skip the validation. It takes a context and a method name as params.
type SkipFn func(ctx context.Context, method string) bool

// ExtractorFunc is a function to extract the token from the context
type ExtractorFunc func(ctx context.Context) (string, error)

// JWTValidator is a validator for JWT tokens
type JWTValidator struct {
	cache  *ttlcache.Cache[string, any]
	config Config
}

const (
	defaultScopeKey   = "scope"
	defaultAuthScheme = "Bearer"
	defaultTTL        = 60 * time.Minute
)

var defaultSkipFn = func(ctx context.Context, method string) bool {
	return false
}

// NewJWTValidator Initializes the validator
func NewJWTValidator(cfg Config) *JWTValidator {

	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = defaultTTL
	}

	cache := ttlcache.New[string, any](
		ttlcache.WithTTL[string, any](cfg.CacheTTL),
	)

	if cfg.Skip == nil {
		cfg.Skip = defaultSkipFn
	}

	if cfg.Extractor == nil {
		cfg.Extractor = defaultExtractorFn
	}

	if cfg.Scheme == "" {
		cfg.Scheme = defaultAuthScheme
	}

	if cfg.ScopeKey == "" {
		cfg.ScopeKey = defaultScopeKey
	}

	if cfg.Algorithm == nil {
		if len(cfg.JwtSecret) > 0 {
			cfg.Algorithm = jwt.SigningMethodHS256
		} else {
			cfg.Algorithm = jwt.SigningMethodRS256
		}
	}

	return &JWTValidator{
		cache:  cache,
		config: cfg,
	}
}
