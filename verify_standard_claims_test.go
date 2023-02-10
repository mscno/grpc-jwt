package grpcjwt

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_verifyStandardClaims(t *testing.T) {
	type args struct {
		user *jwt.Token
		cfg  Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{"ok", args{&jwt.Token{Claims: jwt.MapClaims{"aud": "audience", "iss": "issuer", "scope": []string{"scope"}}}, Config{Audience: "audience", Issuer: "issuer", Scope: []string{"scope"}, ScopeKey: defaultScopeKey}}, assert.NoError},
		{"ok no issuer", args{&jwt.Token{Claims: jwt.MapClaims{"aud": "audience", "scope": []string{"scope"}}}, Config{Audience: "audience", Scope: []string{"scope"}, ScopeKey: defaultScopeKey}}, assert.NoError},
		{"ok no audience", args{&jwt.Token{Claims: jwt.MapClaims{"iss": "issuer", "scope": []string{"scope"}}}, Config{Issuer: "issuer", Scope: []string{"scope"}, ScopeKey: defaultScopeKey}}, assert.NoError},
		{"ok no scopes", args{&jwt.Token{Claims: jwt.MapClaims{"aud": "audience", "iss": "issuer"}}, Config{Audience: "audience", Issuer: "issuer", ScopeKey: defaultScopeKey}}, assert.NoError},
		{"ok scope interface", args{&jwt.Token{Claims: jwt.MapClaims{"aud": "audience", "iss": "issuer", "scope": []interface{}{"scope"}}}, Config{Audience: "audience", Issuer: "issuer", Scope: []string{"scope"}, ScopeKey: defaultScopeKey}}, assert.NoError},
		{"ok scope interface", args{&jwt.Token{Claims: jwt.MapClaims{"aud": "audience", "iss": "issuer", "scope": []interface{}{1, "scope"}}}, Config{Audience: "audience", Issuer: "issuer", Scope: []string{"scope"}, ScopeKey: defaultScopeKey}}, assert.NoError},
		{"ok scope string", args{&jwt.Token{Claims: jwt.MapClaims{"aud": "audience", "iss": "issuer", "scope": "scope otherscope"}}, Config{Audience: "audience", Issuer: "issuer", Scope: []string{"scope"}, ScopeKey: defaultScopeKey}}, assert.NoError},
		{"ok other scope key", args{&jwt.Token{Claims: jwt.MapClaims{"aud": "audience", "iss": "issuer", "otherscopekey": "scope otherscope"}}, Config{Audience: "audience", Issuer: "issuer", Scope: []string{"scope"}, ScopeKey: "otherscopekey"}}, assert.NoError},
		{"bad audience", args{&jwt.Token{Claims: jwt.MapClaims{"aud": "audience", "iss": "issuer", "scope": []string{"scope"}}}, Config{Audience: "bad audience", Issuer: "issuer", Scope: []string{"scope"}, ScopeKey: defaultScopeKey}}, assert.Error},
		{"bad issuer", args{&jwt.Token{Claims: jwt.MapClaims{"aud": "audience", "iss": "issuer", "scope": []string{"scope"}}}, Config{Audience: "audience", Issuer: "bad issuer", Scope: []string{"scope"}, ScopeKey: defaultScopeKey}}, assert.Error},
		{"bad scope", args{&jwt.Token{Claims: jwt.MapClaims{"aud": "audience", "iss": "issuer", "scope": []string{"scope"}}}, Config{Audience: "audience", Issuer: "issuer", Scope: []string{"bad scope"}, ScopeKey: defaultScopeKey}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, verifyStandardClaims(tt.args.user, tt.args.cfg), fmt.Sprintf("verifyStandardClaims(%v, %v)", tt.args.user, tt.args.cfg))
		})
	}
}
