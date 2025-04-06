package api

import (
	"context"
	"fmt"
	"github.com/valyala/fasthttp"
	"log/slog"
	"time"
)

type Server struct {
	srv        *fasthttp.Server
	cancelFunc context.CancelFunc
	errCh      chan error
}

func NewServer() (*Server, error) {
	sv := &Server{
		errCh: make(chan error, 1),
	}

	handler := Chain(Logger, Recovery)(routers)

	sv.srv = &fasthttp.Server{
		Handler: handler,
		Name:    "otp-api",

		ReadBufferSize:  8 * 1024,
		WriteBufferSize: 8 * 1024,

		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,

		MaxRequestsPerConn: 100,
		MaxConnsPerIP:      50,

		MaxRequestBodySize: 1 * 1024 * 1024,

		MaxIdleWorkerDuration: 15 * time.Second,
		ReduceMemoryUsage:     true,
		Concurrency:           0,

		TCPKeepalive:      true,
		DisableKeepalive:  false,
		StreamRequestBody: false,

		LogAllErrors:          false,
		SecureErrorLogMessage: true,

		// Centralized error response
		ErrorHandler: func(ctx *fasthttp.RequestCtx, _ error) {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetContentType("application/json")
			ctx.SetBodyString(`{"code":"internal_error","message":"Internal Server Error"}`)
		},
	}

	return sv, nil
}

func (s *Server) Start(addr string) {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelFunc = cancel

	go func() {
		slog.Info("starting server", "address", addr)
		if err := s.srv.ListenAndServe(addr); err != nil {
			s.errCh <- fmt.Errorf("server error: %w", err)
		}
		<-ctx.Done()
	}()
}

func (s *Server) Stop() {
	slog.Info("shutting down server...")
	s.cancelFunc()

	if err := s.srv.Shutdown(); err != nil {
		slog.Error("failed to shutdown server", "error", err)
	} else {
		slog.Info("server stopped")
	}
}

func (s *Server) Notify() <-chan error {
	return s.errCh
}
