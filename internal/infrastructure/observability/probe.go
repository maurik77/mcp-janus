package observability

import (
	"context"
	"net/http"

	"mcpproxy/internal/utility"
)

type ProbeServer struct {
	srv *http.Server
}

func NewProbeServer(addr string) *ProbeServer {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return &ProbeServer{
		srv: &http.Server{Addr: addr, Handler: mux},
	}
}

func (p *ProbeServer) Start() {
	go func() {
		utility.Logger.Info().Str("addr", p.srv.Addr).Msg("Probe server starting")
		if err := p.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			utility.Logger.Fatal().Err(err).Msg("Probe server failed")
		}
	}()
}

func (p *ProbeServer) Shutdown(ctx context.Context) error {
	return p.srv.Shutdown(ctx)
}
