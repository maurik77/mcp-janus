package telemetry

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds OpenTelemetry configuration
type Config struct {
	ServiceName    string
	ServiceVersion string
	OTLPEndpoint   string
	Enabled        bool
}

// Telemetry holds the telemetry providers and shutdown functions
type Telemetry struct {
	TracerProvider *sdktrace.TracerProvider
	MeterProvider  *sdkmetric.MeterProvider
	Tracer         trace.Tracer
	Meter          metric.Meter
	shutdownFuncs  []func(context.Context) error
}

// Initialize sets up OpenTelemetry tracing and metrics
func Initialize(ctx context.Context, cfg Config) (*Telemetry, error) {
	if !cfg.Enabled {
		log.Println("OpenTelemetry is disabled")
		return &Telemetry{
			Tracer: otel.Tracer(cfg.ServiceName),
			Meter:  otel.Meter(cfg.ServiceName),
		}, nil
	}

	t := &Telemetry{
		shutdownFuncs: make([]func(context.Context) error, 0),
	}

	// Create resource
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
			semconv.ServiceVersionKey.String(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Setup trace provider
	tracerProvider, err := setupTraceProvider(ctx, cfg, res)
	if err != nil {
		return nil, fmt.Errorf("failed to setup trace provider: %w", err)
	}
	t.TracerProvider = tracerProvider
	t.shutdownFuncs = append(t.shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	// Setup meter provider
	meterProvider, err := setupMeterProvider(ctx, cfg, res)
	if err != nil {
		return nil, fmt.Errorf("failed to setup meter provider: %w", err)
	}
	t.MeterProvider = meterProvider
	t.shutdownFuncs = append(t.shutdownFuncs, meterProvider.Shutdown)
	otel.SetMeterProvider(meterProvider)

	// Set global propagator for context propagation (W3C Trace Context)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Create tracer and meter instances
	t.Tracer = otel.Tracer(cfg.ServiceName)
	t.Meter = otel.Meter(cfg.ServiceName)

	log.Printf("OpenTelemetry initialized successfully (endpoint: %s)", cfg.OTLPEndpoint)
	return t, nil
}

// setupTraceProvider creates and configures the trace provider
func setupTraceProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdktrace.TracerProvider, error) {
	// Create OTLP HTTP trace exporter
	traceExporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(cfg.OTLPEndpoint),
		otlptracehttp.WithInsecure(), // Use WithTLSClientConfig for production
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create trace provider with batch span processor
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter,
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	return tracerProvider, nil
}

// setupMeterProvider creates and configures the meter provider
func setupMeterProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdkmetric.MeterProvider, error) {
	// Create OTLP HTTP metric exporter
	metricExporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpoint(cfg.OTLPEndpoint),
		otlpmetrichttp.WithInsecure(), // Use WithTLSClientConfig for production
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create metric exporter: %w", err)
	}

	// Create meter provider with periodic reader
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter,
			sdkmetric.WithInterval(10*time.Second),
		)),
		sdkmetric.WithResource(res),
	)

	return meterProvider, nil
}

// Shutdown gracefully shuts down all telemetry providers
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t == nil {
		return nil
	}

	var err error
	for _, shutdown := range t.shutdownFuncs {
		if shutdownErr := shutdown(ctx); shutdownErr != nil {
			err = fmt.Errorf("shutdown error: %w", shutdownErr)
		}
	}
	return err
}
