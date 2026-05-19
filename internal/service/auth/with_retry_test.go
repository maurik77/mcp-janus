package auth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithRetry(t *testing.T) {
	t.Run("success on first attempt", func(t *testing.T) {
		calls := 0
		result, err := withRetry(3, 0, func() (string, error) {
			calls++
			return "ok", nil
		})
		require.NoError(t, err)
		assert.Equal(t, "ok", result)
		assert.Equal(t, 1, calls)
	})

	t.Run("success after initial failures", func(t *testing.T) {
		calls := 0
		result, err := withRetry(3, 0, func() (string, error) {
			calls++
			if calls < 3 {
				return "", fmt.Errorf("transient error %d", calls)
			}
			return "recovered", nil
		})
		require.NoError(t, err)
		assert.Equal(t, "recovered", result)
		assert.Equal(t, 3, calls)
	})

	t.Run("all attempts fail returns last error", func(t *testing.T) {
		calls := 0
		_, err := withRetry(3, 0, func() (string, error) {
			calls++
			return "", fmt.Errorf("attempt %d failed", calls)
		})
		require.Error(t, err)
		assert.Equal(t, "attempt 3 failed", err.Error())
		assert.Equal(t, 3, calls)
	})

	t.Run("single attempt exhausted immediately", func(t *testing.T) {
		calls := 0
		_, err := withRetry(1, 0, func() (int, error) {
			calls++
			return 0, fmt.Errorf("only attempt failed")
		})
		require.Error(t, err)
		assert.Equal(t, 1, calls)
	})

	t.Run("zero result type on all failures", func(t *testing.T) {
		result, err := withRetry(2, 0, func() (int, error) {
			return 99, fmt.Errorf("always fail")
		})
		require.Error(t, err)
		assert.Equal(t, 0, result)
	})
}
