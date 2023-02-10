# grpc-jwt-auth
[![Build Status](https://travis-ci.org/soheilhy/grpc-jwt-auth.svg?branch=master)](https://travis-ci.org/soheilhy/grpc-jwt-auth)
[![GoDoc](https://godoc.org/github.com/soheilhy/grpc-jwt-auth?status.svg)](https://godoc.org/github.com/soheilhy/grpc-jwt-auth)

This is a simple Go package that provides a gRPC server interceptor for JWT authentication.
The package currently only supports asymmetric keys, and can be used with any gRPC server.
Symmetric keys are not supported, but can be added if there is a need for it.

The package uses the [github.com/golang-jwt/jwt/v4](github.com/golang-jwt/jwt/v4) package for JWT validation, 
and the [github.com/MicahParks/keyfunc](github.com/MicahParks/keyfunc) package for key fetching and parsing jwks key sets.

### Todos

- Add support for symmetric keys and other algorithms
- Add support for custom claims
- Add support for storing the claims in the context for later use

## Installation

```bash
go get github.com/mscno/grpc-jwt
```

## Usage

Basic usage with the built in `UnaryServerInterceptor`

```go
import (
    "github.com/mscno/grpc-jwt"
)

func main() {
    validator := grpc_jwt.NewJWTValidator(Config{
        JwksUrl:   "http://localhost:9999/.well-known/jwks.json",
        Algorithm: jwt.SigningMethodRS256,
        CacheTTL:  60 * time.Minute,
        Audience:  "my-audience",
        Issuer:    "my-issuer",
    })
	
    myServer := grpc.NewServer(
        grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
            grpc_jwt.UnaryServerInterceptor(validator),
            grpc_recovery.UnaryServerInterceptor(),
        )),
    ) 
    
```

The validator can also be used with the `grpc_auth` package. 
In which case it is recommended that you use the `SetMethodNameInContext` interceptor to set the method name in the context. 
This is useful for the `AuthFunc` function to determine which method is being called, and it, and it is a requirement for the `skipFn` logic to work correctly.

```go
import (
    "github.com/mscno/grpc-jwt"
)

func main() {
    validator := grpc_jwt.NewJWTValidator(Config{
        JwksUrl:   "http://localhost:9999/.well-known/jwks.json",
        Algorithm: jwt.SigningMethodRS256,
        CacheTTL:  60 * time.Minute,
        Audience:  "my-audience",
        Issuer:    "my-issuer",
    })

    myServer := grpc.NewServer(
        grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
            grpc_jwt.SetMethodNameInContext(),
            grpc_auth.UnaryServerInterceptor(validator.AuthFunc),
            grpc_recovery.UnaryServerInterceptor(),
        )),
    )
```

## Coverage

Test coverage is currently `99%`.

```shell
$ go test -cover -race
PASS
coverage: 99.3% of statements
ok      github.com/mscno/grpc-jwt       0.395s
```