package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestJTIStore(t *testing.T) {
	t.Run("first use returns false (not seen)", func(t *testing.T) {
		s := newJTIStore()
		exp := time.Now().Add(time.Minute)
		assert.False(t, s.Seen("jti-1", exp))
	})

	t.Run("second use returns true (replay)", func(t *testing.T) {
		s := newJTIStore()
		exp := time.Now().Add(time.Minute)
		s.Seen("jti-1", exp) //nolint:errcheck
		assert.True(t, s.Seen("jti-1", exp))
	})

	t.Run("different jti values are independent", func(t *testing.T) {
		s := newJTIStore()
		exp := time.Now().Add(time.Minute)
		s.Seen("jti-a", exp) //nolint:errcheck
		assert.False(t, s.Seen("jti-b", exp))
	})

	t.Run("expired entry is pruned and not replayed", func(t *testing.T) {
		s := newJTIStore()
		// Register with already-expired expiry.
		exp := time.Now().Add(-time.Second)
		s.Seen("jti-old", exp) //nolint:errcheck

		// Any subsequent call prunes expired entries; re-registering should succeed.
		assert.False(t, s.Seen("jti-old", time.Now().Add(time.Minute)))
	})
}
