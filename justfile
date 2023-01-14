run: test

test:
    go test ./...

cover:
    go test -coverprofile=coverage.out ./...