package utility

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

var Logger zerolog.Logger

func ConfigureLogging(logLevel string, logFormat string) {
	var logWriter = os.Stdout

	logger := zerolog.New(logWriter).With().Timestamp().Logger()

	loggingLevel, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		loggingLevel = zerolog.ErrorLevel
	}

	zerolog.SetGlobalLevel(loggingLevel)

	Logger = logger
}

func LogHttpRequest(req *http.Request) {
	// Log request method and URL
	Logger.Info().Str("method", req.Method).Str("host", req.Host).Str("url", req.URL.String()).Msg("Upstream request")

	// Log all headers
	for k, v := range req.Header {
		Logger.Debug().Str("header", k).Str("value", v[0]).Msg("Request header")
	}

	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		Logger.Debug().Str("body", string(bodyBytes)).Msg("Upstream request body")
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	} else {
		Logger.Debug().Msg("Upstream request body: empty")
	}
}

func LogHttpResponse(resp *http.Response) {
	// Log response status
	Logger.Info().Int("status_code", resp.StatusCode).Msg("Upstream response")

	// Log all headers
	for k, v := range resp.Header {
		Logger.Debug().Str("header", k).Str("value", strings.Join(v, ", ")).Msg("Response header")
	}

	if resp.Body != nil {
		bodyBytes, _ := io.ReadAll(resp.Body)
		Logger.Debug().Str("body", string(bodyBytes)).Msg("Upstream response body")
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	} else {
		Logger.Debug().Msg("Upstream response body: empty")
	}
}
