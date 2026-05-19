package utility

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigureLogging_ValidLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		ConfigureLogging(level, "json")
		assert.NotNil(t, Logger)
	}
}

func TestConfigureLogging_InvalidLevel_FallsBackToError(t *testing.T) {
	ConfigureLogging("not-a-level", "json")
	assert.NotNil(t, Logger)
}

func TestLogHttpRequest_WithBody(t *testing.T) {
	ConfigureLogging("error", "json")

	body := "hello body"
	req, _ := http.NewRequest("POST", "http://upstream/path", strings.NewReader(body))
	req.Header.Set("X-Custom", "value")

	LogHttpRequest(req)

	// Body must still be readable after logging
	remaining, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	assert.Equal(t, body, string(remaining))
}

func TestLogHttpRequest_NilBody(t *testing.T) {
	ConfigureLogging("error", "json")

	req, _ := http.NewRequest("GET", "http://upstream/path", nil)
	assert.NotPanics(t, func() { LogHttpRequest(req) })
}

func TestLogHttpResponse_WithBody(t *testing.T) {
	ConfigureLogging("error", "json")

	body := "response body"
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{},
	}

	LogHttpResponse(resp)

	// Body must still be readable after logging
	remaining, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, body, string(remaining))
}

func TestLogHttpResponse_NilBody(t *testing.T) {
	ConfigureLogging("error", "json")

	resp := &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     http.Header{},
		Body:       nil,
		Request:    &http.Request{},
	}

	assert.NotPanics(t, func() { LogHttpResponse(resp) })
}

func TestLogHttpRequest_BodyIsResetAfterRead(t *testing.T) {
	ConfigureLogging("debug", "json")

	original := "important payload"
	req, _ := http.NewRequest("POST", "http://upstream/", bytes.NewBufferString(original))

	LogHttpRequest(req)

	// Second read must return the same content (body was reset)
	got, _ := io.ReadAll(req.Body)
	assert.Equal(t, original, string(got))
}
