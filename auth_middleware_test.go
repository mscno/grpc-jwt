package grpcjwt

import (
	"context"
	"crypto/md5"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

var defaultValidator = NewJWTValidator(Config{
	JwksUrl:   "http://localhost:9999/.well-known/jwks.json",
	Algorithm: jwt.SigningMethodRS256,
	CacheTTL:  60,
	Audience:  "my-audience",
	Issuer:    "my-issuer",
})

var badValidator = NewJWTValidator(Config{
	JwksUrl:   "http://bad-url",
	Algorithm: jwt.SigningMethodRS256,
	CacheTTL:  60,
	Audience:  "my-audience",
	Issuer:    "my-issuer",
})

var badJsonValidator = NewJWTValidator(Config{
	JwksUrl:   "http://localhost:9999/.well-known/bad-jwks.json",
	Algorithm: jwt.SigningMethodRS256,
	CacheTTL:  60,
	Audience:  "my-audience",
	Issuer:    "my-issuer",
})

var missingKidValidator = NewJWTValidator(Config{
	JwksUrl:   "http://localhost:9999/.well-known/missing-jwks.json",
	Algorithm: jwt.SigningMethodRS256,
	CacheTTL:  60,
	Audience:  "my-audience",
	Issuer:    "my-issuer",
})

var badPemValidator = NewJWTValidator(Config{
	JwksUrl:   "http://localhost:9999/.well-known/bad-pem.json",
	Algorithm: jwt.SigningMethodRS256,
	CacheTTL:  60,
	Audience:  "my-audience",
	Issuer:    "my-issuer",
})

func TestValidator(t *testing.T) {

	go startJwksServer()

	type args struct {
		ctx       context.Context
		req       interface{}
		validator *JWTValidator
		info      *grpc.UnaryServerInfo
	}
	tests := []struct {
		name string
		args args
		err  error
	}{
		{
			name: "no metadata",
			args: args{
				ctx: context.Background(),
			},
			err: ErrMissingKey,
		},
		{
			name: "no authorization header",
			args: args{
				ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs()),
			},
			err: ErrMissingKey,
		},
		{
			name: "no token should be invalid key",
			args: args{
				ctx: ctx(""),
			},
			err: ErrMissingKey,
		},
		{
			name: "invalid token should be invalid key",
			args: args{
				ctx: ctx("bad-token"),
			},
			err: ErrBadAuthScheme,
		},
		{
			name: "invalid encoding should result in bad encoding error",
			args: args{
				ctx: ctx("Bearer bad-token.bad-token.bad-token"),
			},
			err: ErrTokenMalformed,
		},
		{
			name: "good token should not result in error",
			args: args{
				ctx: ctx("Bearer " + getJwksToken("my-audience", "my-issuer", "my-user", time.Now().Add(time.Minute))),
			},
			err: nil,
		},
		{
			name: "bad audience should result in error",
			args: args{
				ctx: ctx("Bearer " + getJwksToken("bad-audience", "my-issuer", "my-user", time.Now().Add(time.Minute))),
			},
			err: ErrTokenInvalidAudience,
		},
		{
			name: "bad issuer should be err bad issuer",
			args: args{
				ctx: ctx("Bearer " + getJwksToken("my-audience", "bad-issuer", "my-user", time.Now().Add(time.Minute))),
			},
			err: ErrTokenInvalidIssuer,
		},
		{
			name: "expired token should be expired",
			args: args{
				ctx: ctx("Bearer " + getJwksToken("my-audience", "bad-issuer", "my-user", time.Now().Add(-time.Minute*60))),
			},
			err: ErrTokenExpired,
		},
		{
			name: "invalid signature algorithm method",
			args: args{
				ctx: ctx("Bearer " + badMethodToken(time.Now())),
			},
			err: ErrBadAlgorithm,
		},
		{
			name: "invalid signature",
			args: args{
				ctx: ctx("Bearer " + badSignatureToken(time.Now().Add(time.Minute))),
			},
			err: ErrSignatureInvalid,
		},
		{
			name: "bad validator should result in error",
			args: args{
				ctx:       ctx("Bearer " + getJwksToken("my-audience", "my-issuer", "my-user", time.Now().Add(time.Minute))),
				validator: badValidator,
			},
			err: ErrJwksLoadError,
		},
		{
			name: "missing public error",
			args: args{
				ctx:       ctx("Bearer " + getJwksToken("my-audience", "my-issuer", "my-user", time.Now().Add(time.Minute))),
				validator: missingKidValidator,
			},
			err: ErrKIDNotFound,
		},
		{
			name: "bad json validator should result in error",
			args: args{
				ctx:       ctx("Bearer " + getJwksToken("my-audience", "my-issuer", "my-user", time.Now().Add(time.Minute))),
				validator: badJsonValidator,
			},
			err: ErrJwksLoadError,
		},
		{
			name: "bad pem validator should result in error",
			args: args{
				ctx:       ctx("Bearer " + getJwksToken("my-audience", "my-issuer", "my-user", time.Now().Add(time.Minute))),
				validator: badPemValidator,
			},
			err: ErrKIDNotFound,
		},
		{
			name: "ErrTokenNotValidYet",
			args: args{
				ctx: ctx("Bearer " + getJwksTokenWithTimes("my-audience", "my-issuer", "my-user", time.Now().Add(time.Minute), time.Now().Add(time.Minute), time.Now())),
			},
			err: ErrTokenNotValidYet,
		},
		{
			name: "ErrTokenUsedBeforeIssued",
			args: args{
				ctx: ctx("Bearer " + getJwksTokenWithTimes("my-audience", "my-issuer", "my-user", time.Now().Add(time.Minute), time.Now().Add(-time.Minute), time.Now().Add(time.Minute))),
			},
			err: ErrTokenUsedBeforeIssued,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := defaultValidator
			if tt.args.validator != nil {
				validator = tt.args.validator
			}
			f := UnaryServerInterceptor(validator)
			_, err := f(tt.args.ctx, tt.args.req, tt.args.info, passThroughHandler)
			err = errors.Cause(err)
			assert.Equal(t, tt.err, err)
			if tt.err != nil {
				require.Error(t, err)
				assert.Equal(t, tt.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func ctx(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", token))
}

func method(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{
		FullMethod: method,
	}
}

func passThroughHandler(ctx context.Context, req interface{}) (interface{}, error) {
	return nil, nil
}

const publicKeyBytes = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0MJjkyBLJDD7iLzFwbJj
26y6m7d1IvuhkiqTkKspMygx7hBOtprWdt3E6l2a3qe1AwJubzdn/prm/oaJwsKQ
1iKXrsiJ/kq5tvLxamCXicRva5KpyIZye8YQs6AURDCKTiF4rswttasLjjs9Lg1K
5bmOw0qPJ74LHSnAaNiTLjTRSX1bexf159ZVVAsJnzCmH5bvSEggss7ypHmdKOP+
GU+M/RtiimMSxL85XMlo/1pwxajUaVJeTfaUTwuJrWF0c+ygD2Ca9BFaFTVlJiPE
jgBIOb0DDQPurlYObZy5iYUqvSkYjp+tqZuSc4ftLIfZIoIH61i+5EUEO+1JMBRG
6QIDAQAB
-----END PUBLIC KEY-----`

const privateKeyBytes = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA0MJjkyBLJDD7iLzFwbJj26y6m7d1IvuhkiqTkKspMygx7hBO
tprWdt3E6l2a3qe1AwJubzdn/prm/oaJwsKQ1iKXrsiJ/kq5tvLxamCXicRva5Kp
yIZye8YQs6AURDCKTiF4rswttasLjjs9Lg1K5bmOw0qPJ74LHSnAaNiTLjTRSX1b
exf159ZVVAsJnzCmH5bvSEggss7ypHmdKOP+GU+M/RtiimMSxL85XMlo/1pwxajU
aVJeTfaUTwuJrWF0c+ygD2Ca9BFaFTVlJiPEjgBIOb0DDQPurlYObZy5iYUqvSkY
jp+tqZuSc4ftLIfZIoIH61i+5EUEO+1JMBRG6QIDAQABAoIBABSVdjgFkSMqaULc
SiuFKW95opTEDBq88Pt2k0JKfi97ISE2HmzG66qgx0/Mlv6pTqHTVYxFzE1AfNJP
9blscdeLZaVoRKL8Pz+YyNESYR7Gba4PsgoBp7wolXEAsb7fgmOdzUZ+/2rQSL1n
ferSiLYKC9eZvG/Qv0vK2Bv+btS5Vup1RkWYokSESHjEozJZlS3y4ds8hKRHkmJj
6tR5NWjpTQYp24RJvUCP1rr7LyGh04CHzeA4mqrH1L7gddhSPaAzMrL7QjhODk4N
v6eQ4XzcUKsUk3irYF2FglmqH91w/n7NYE4OiestVLznpJo3CRe7yojPC1N1ZX6z
agmvjgECgYEA6MwQQS/pzeFJZfx58lloPSMO6SQoEkUMuyU0ykx8iw4XHUcmmtT3
9PNhOWQWwczeDNadY7FrWKGAcK0TwU1I8aWcA4qCBADUNcuUordq3SVOuZ1OR7er
+LsRjZbRcdPw9HQOQNKA7Erk+87UBGQi7CRxH8AGSq3QN4NzzRftZCECgYEA5ZD9
MpVinRXmWWSEVfxNspyoW8ljpX5PTa8It5bqbNvj+iarQ9wxS4XlCj08wDPLf6an
WohDxKXx1vykKfVyC7O9SF330TQKQBgGvkKl2K6Vm0/sh/EAcnfUE9kSr+rKA20p
I9IIus4QhUg5MqIPYdRvGomL0Bo4i5ZypDi7ickCgYBZPZjhlF95Z+p+KRoKWFHI
Vf8qSoz96/BkcW/aORXpLH6Z36Oh6RAgm4fiu0aqBkH9A+yTwfiXolmdWAvhpyHW
WJkFFnye0j6HXMJe2hciLWIPb4kJnxRSpkulTnJ9wzR0UWUBXnDDpDZBfVjzUfu9
MH8ZH8CJsjXGgiLLNWfwYQKBgDgTv9YAadNnixphFHaQqEYuQG4TdtTxUtvuGtoF
8oPe/wSXN5TfD+eb8IQcy19EB7zJ7+2MhclepAHZOxzIyTAUmvM3iRbAeJSJifQm
Aa85jnAfCO94LpzHqrWifA8e8nP90WPfpaREPALizp4QumMyamV4HgAat59Zg+2b
siwJAoGAS6Li1lYBQ8Oa+to/32Q6s8EhRwuUKmKarKXdfzoDUvBY9kS79Rc2S/QC
tMJUkdwfbIogI3LM3oYZ56Yxhfx9nl9E7O010QmgmODtnpz9YqiKz+yPYGfHLfnM
gDPJtHuaw8FUOdnsSSzGF1VhMVbcUnNPEyhDvz2Aj7lfrN7x/r4=
-----END RSA PRIVATE KEY-----`

func startJwksServer() error {
	pubKey := getTestPublicKey()
	k := publicKeyToJwks([]byte(publicKeyBytes), pubKey)
	set := jwtKeys{Keys: []jwtKey{k}}

	http.HandleFunc("/.well-known/bad-jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("bad json"))
	})

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(set)
	})

	kbad := k
	kbad.Kid = "bad kid"
	badset := jwtKeys{Keys: []jwtKey{kbad}}
	http.HandleFunc("/.well-known/missing-jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(badset)
	})

	kbad2 := k
	kbad2.X5c = []string{"bad key"}
	kbad2.X5t = "bad key"
	kbad2.E = "bad e"
	kbad2.N = "bad n"
	badset2 := jwtKeys{Keys: []jwtKey{kbad2}}
	http.HandleFunc("/.well-known/bad-pem.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(badset2)
	})

	l, err := net.Listen("tcp", ":9999")
	if err != nil {
		return err
	}
	return http.Serve(l, http.DefaultServeMux)
}

func getKidFromPrivate(key []byte) string {
	signKeyBytePrint := md5.Sum(key)
	signKeyStringPrint := fmt.Sprintf("%x", signKeyBytePrint)
	return signKeyStringPrint
}

func publicKeyToJwks(payload []byte, v *rsa.PublicKey) jwtKey {
	return jwtKey{
		Alg: "RS256",
		Kty: "RSA",
		Use: "sig",
		X5c: []string{unpadStringToByte(payload)},
		E:   getExponentRSA(v),
		N:   getModulusRSA(v),
		Kid: getKidFromPrivate([]byte(privateKeyBytes)),
		X5t: getKidFromPrivate([]byte(privateKeyBytes)),
	}
}

func unpadStringToByte(key []byte) string {
	keyString := strings.TrimSuffix(strings.TrimPrefix(string(key), "-----BEGIN PUBLIC KEY-----\n"), "\n-----END PUBLIC KEY-----")
	keyString = strings.ReplaceAll(keyString, "\n", "")
	return keyString
}

func getExponentRSA(key *rsa.PublicKey) string {
	v := uint32(key.E)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	var start int
	for k, v := range buf {
		if v != 0 {
			start = k
			break
		}
	}
	trimmedByte := buf[start:len(buf)]
	return base64.URLEncoding.EncodeToString(trimmedByte)
}

func getModulusRSA(key *rsa.PublicKey) string {
	bytes := key.N.Bytes()
	var start int
	for k, v := range bytes {
		if v != 0 {
			start = k
			break
		}
	}
	trimmedBytes := bytes[start:len(bytes)]
	return base64.URLEncoding.EncodeToString(trimmedBytes)
}

func getTestPublicKey() *rsa.PublicKey {
	pubKey, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyBytes))
	return pubKey
}

func getTestPrivateKey() *rsa.PrivateKey {
	pk, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyBytes))
	return pk
}

func getJwksToken(aud string, iss string, sub string, exp time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": aud,
		"iss": iss,
		"sub": sub,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
		"kid": getKidFromPrivate([]byte(privateKeyBytes)),
	})
	token.Header["kid"] = getKidFromPrivate([]byte(privateKeyBytes))

	signedToken, err := token.SignedString(getTestPrivateKey())
	if err != nil {
		panic(err)
	}
	return signedToken
}

func getJwksTokenWithTimes(aud string, iss string, sub string, exp time.Time, nbf time.Time, iat time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": aud,
		"iss": iss,
		"sub": sub,
		"iat": iat.Unix(),
		"exp": exp.Unix(),
		"nbf": nbf.Unix(),
		"kid": getKidFromPrivate([]byte(privateKeyBytes)),
	})
	token.Header["kid"] = getKidFromPrivate([]byte(privateKeyBytes))

	signedToken, err := token.SignedString(getTestPrivateKey())
	if err != nil {
		panic(err)
	}
	return signedToken
}

func badMethodToken(exp time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
		"kid": getKidFromPrivate([]byte(privateKeyBytes)),
	})
	token.Header["kid"] = getKidFromPrivate([]byte(privateKeyBytes))

	tokenString, _ := token.SigningString()

	return strings.Join([]string{tokenString, "bad"}, ".")
}

func badSignatureToken(exp time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
		"kid": getKidFromPrivate([]byte(privateKeyBytes)),
	})
	token.Header["kid"] = getKidFromPrivate([]byte(privateKeyBytes))

	tokenString, _ := token.SigningString()

	return strings.Join([]string{tokenString, "bad"}, ".")
}

type jwtKey struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	Kid string   `json:"kid"`
	X5t string   `json:"x5t"`
}

type jwtKeys struct {
	Keys []jwtKey `json:"keys"`
}
