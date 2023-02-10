package grpcjwt

import "strings"

func checkScheme(scheme string, authHeader string) (string, error) {
	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == scheme) {
		return "", ErrBadAuthScheme
	}
	return parts[1], nil
}
