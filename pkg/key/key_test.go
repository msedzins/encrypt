package key

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewKeyFromBytes(t *testing.T) {
	tests := []struct {
		keyBytes []byte
		expected error
	}{
		{make([]byte, KeySize128), nil},
		{make([]byte, KeySize192), nil},
		{make([]byte, KeySize256), nil},
		{make([]byte, 10), ErrInvalidKeySize},
	}

	for _, test := range tests {
		key, err := NewKeyFromBytes(test.keyBytes)
		if test.expected != nil {
			assert.Nil(t, key)
			assert.Equal(t, test.expected, err)
		} else {
			assert.NotNil(t, key)
			assert.Nil(t, err)
			assert.Equal(t, len(test.keyBytes), len(key.Bytes()))
			key.Destroy()
		}
	}
}
func TestKeySize_IsValid(t *testing.T) {
	tests := []struct {
		size     KeySize
		expected bool
	}{
		{KeySize128, true},
		{KeySize192, true},
		{KeySize256, true},
		{KeySize(10), false},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, test.size.IsValid())
	}
}

func TestNewKey(t *testing.T) {
	tests := []struct {
		size     KeySize
		expected error
	}{
		{KeySize128, nil},
		{KeySize192, nil},
		{KeySize256, nil},
		{KeySize(10), ErrInvalidKeySize},
	}

	for _, test := range tests {
		key, err := NewKey(test.size)
		if test.expected != nil {
			assert.Nil(t, key)
			assert.Equal(t, test.expected, err)
		} else {
			assert.NotNil(t, key)
			assert.Nil(t, err)
			assert.Equal(t, int(test.size), len(key.Bytes()))
			key.Destroy()
		}
	}
}

func TestKey_Destroy(t *testing.T) {
	key, err := NewKey(KeySize128)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	key.Destroy()
	assert.Nil(t, key.key)
}

func TestKey_Bytes(t *testing.T) {
	key, err := NewKey(KeySize128)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	bytes := key.Bytes()
	assert.Equal(t, int(KeySize128), len(bytes))

	key.Destroy()
	assert.Nil(t, key.Bytes())
}
