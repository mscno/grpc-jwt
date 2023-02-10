package grpcjwt

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetMethodName(t *testing.T) {
	info := method("my_method")
	ctx := context.Background()
	name, ok := GetMethodName(ctx)
	assert.Empty(t, name)
	assert.False(t, ok)
	fn := SetMethodNameInContext()
	_, err := fn(ctx, nil, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		name, ok = GetMethodName(ctx)
		assert.Equal(t, "my_method", name)
		assert.True(t, ok)
		return nil, nil
	})
	assert.NoError(t, err)
}
