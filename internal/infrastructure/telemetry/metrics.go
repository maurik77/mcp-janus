package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds all business metrics for the MCP proxy
type Metrics struct {
	// Authentication metrics
	AuthRequestsTotal       metric.Int64Counter
	AuthSuccessTotal        metric.Int64Counter
	AuthFailureTotal        metric.Int64Counter
	TokenExchangeTotal      metric.Int64Counter
	TokenExchangeDuration   metric.Float64Histogram
	ClientRegistrationTotal metric.Int64Counter

	// Proxy metrics
	ProxyRequestsTotal    metric.Int64Counter
	ProxyRequestDuration  metric.Float64Histogram
	ProxyErrorsTotal      metric.Int64Counter
	UpstreamRequestsTotal metric.Int64Counter
	UpstreamErrorsTotal   metric.Int64Counter

	// Token validation metrics
	TokenValidationTotal    metric.Int64Counter
	TokenValidationFailures metric.Int64Counter
	TokenDecryptionFailures metric.Int64Counter
}

// InitializeMetrics creates all business metrics
func InitializeMetrics(meter metric.Meter) (*Metrics, error) {
	m := &Metrics{}

	var err error

	// Authentication metrics
	m.AuthRequestsTotal, err = meter.Int64Counter(
		"mcp.proxy.auth.requests.total",
		metric.WithDescription("Total number of authentication requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	m.AuthSuccessTotal, err = meter.Int64Counter(
		"mcp.proxy.auth.success.total",
		metric.WithDescription("Total number of successful authentications"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	m.AuthFailureTotal, err = meter.Int64Counter(
		"mcp.proxy.auth.failure.total",
		metric.WithDescription("Total number of failed authentications"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	m.TokenExchangeTotal, err = meter.Int64Counter(
		"mcp.proxy.token.exchange.total",
		metric.WithDescription("Total number of token exchanges"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	m.TokenExchangeDuration, err = meter.Float64Histogram(
		"mcp.proxy.token.exchange.duration",
		metric.WithDescription("Duration of token exchange operations"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, err
	}

	m.ClientRegistrationTotal, err = meter.Int64Counter(
		"mcp.proxy.client.registration.total",
		metric.WithDescription("Total number of client registrations"),
		metric.WithUnit("{registration}"),
	)
	if err != nil {
		return nil, err
	}

	// Proxy metrics
	m.ProxyRequestsTotal, err = meter.Int64Counter(
		"mcp.proxy.requests.total",
		metric.WithDescription("Total number of proxy requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	m.ProxyRequestDuration, err = meter.Float64Histogram(
		"mcp.proxy.request.duration",
		metric.WithDescription("Duration of proxy requests"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, err
	}

	m.ProxyErrorsTotal, err = meter.Int64Counter(
		"mcp.proxy.errors.total",
		metric.WithDescription("Total number of proxy errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, err
	}

	m.UpstreamRequestsTotal, err = meter.Int64Counter(
		"mcp.proxy.upstream.requests.total",
		metric.WithDescription("Total number of upstream requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	m.UpstreamErrorsTotal, err = meter.Int64Counter(
		"mcp.proxy.upstream.errors.total",
		metric.WithDescription("Total number of upstream errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, err
	}

	// Token validation metrics
	m.TokenValidationTotal, err = meter.Int64Counter(
		"mcp.proxy.token.validation.total",
		metric.WithDescription("Total number of token validations"),
		metric.WithUnit("{validation}"),
	)
	if err != nil {
		return nil, err
	}

	m.TokenValidationFailures, err = meter.Int64Counter(
		"mcp.proxy.token.validation.failures.total",
		metric.WithDescription("Total number of token validation failures"),
		metric.WithUnit("{failure}"),
	)
	if err != nil {
		return nil, err
	}

	m.TokenDecryptionFailures, err = meter.Int64Counter(
		"mcp.proxy.token.decryption.failures.total",
		metric.WithDescription("Total number of token decryption failures"),
		metric.WithUnit("{failure}"),
	)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// RecordAuthRequest records an authentication request
func (m *Metrics) RecordAuthRequest(ctx context.Context, clientID string) {
	m.AuthRequestsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("client.id", clientID),
	))
}

// RecordAuthSuccess records a successful authentication
func (m *Metrics) RecordAuthSuccess(ctx context.Context, clientID string) {
	m.AuthSuccessTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("client.id", clientID),
	))
}

// RecordAuthFailure records a failed authentication
func (m *Metrics) RecordAuthFailure(ctx context.Context, clientID string, reason string) {
	m.AuthFailureTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("client.id", clientID),
		attribute.String("reason", reason),
	))
}

// RecordTokenExchange records a token exchange operation
func (m *Metrics) RecordTokenExchange(ctx context.Context, duration time.Duration, success bool) {
	m.TokenExchangeTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.Bool("success", success),
	))
	m.TokenExchangeDuration.Record(ctx, float64(duration.Milliseconds()))
}

// RecordClientRegistration records a client registration
func (m *Metrics) RecordClientRegistration(ctx context.Context, success bool) {
	m.ClientRegistrationTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.Bool("success", success),
	))
}

// RecordProxyRequest records a proxy request
func (m *Metrics) RecordProxyRequest(ctx context.Context, method string, path string, statusCode int, duration time.Duration) {
	m.ProxyRequestsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("http.method", method),
		attribute.String("http.path", path),
		attribute.Int("http.status_code", statusCode),
	))
	m.ProxyRequestDuration.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("http.method", method),
	))
}

// RecordProxyError records a proxy error
func (m *Metrics) RecordProxyError(ctx context.Context, errorType string) {
	m.ProxyErrorsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("error.type", errorType),
	))
}

// RecordUpstreamRequest records an upstream request
func (m *Metrics) RecordUpstreamRequest(ctx context.Context, upstream string, success bool) {
	m.UpstreamRequestsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("upstream", upstream),
		attribute.Bool("success", success),
	))
	if !success {
		m.UpstreamErrorsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("upstream", upstream),
		))
	}
}

// RecordTokenValidation records a token validation attempt
func (m *Metrics) RecordTokenValidation(ctx context.Context, success bool, reason string) {
	m.TokenValidationTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.Bool("success", success),
	))
	if !success {
		m.TokenValidationFailures.Add(ctx, 1, metric.WithAttributes(
			attribute.String("reason", reason),
		))
	}
}

// RecordTokenDecryptionFailure records a token decryption failure
func (m *Metrics) RecordTokenDecryptionFailure(ctx context.Context) {
	m.TokenDecryptionFailures.Add(ctx, 1)
}
