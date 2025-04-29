package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ja7ad/otp/internal/app/api"
)

var (
	serve  *string
	apiKey *string
	ver    *bool
)

func init() {
	serve = flag.String("serve", ":8080", "http listen address")

	flag.Parse()
}

func main() {
	srv, err := api.NewServer()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	srv.Start(*serve)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-interrupt:
		slog.Warn("termination signal received", "signal", sig.String())
		srv.Stop()
	case err := <-srv.Notify():
		slog.Error("server encountered an error", "error", err)
	}
}
