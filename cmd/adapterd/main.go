package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LaokeQwQ/CheeseWAF-Adapters/internal/adapter/httpserver"
	"github.com/LaokeQwQ/CheeseWAF-Adapters/internal/config"
	"github.com/LaokeQwQ/CheeseWAF-Adapters/internal/coreclient"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		fail(err)
	}
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "adapter listen address")
	flag.StringVar(&cfg.CoreURL, "core-url", cfg.CoreURL, "CheeseWAF core URL")
	flag.StringVar(&cfg.FailMode, "fail-mode", cfg.FailMode, "core failure mode: closed or open")
	flag.DurationVar(&cfg.RequestTimeout, "request-timeout", cfg.RequestTimeout, "inline inspection timeout")
	flag.Parse()
	if err := cfg.Validate(); err != nil {
		fail(err)
	}

	core, err := coreclient.New(coreclient.Config{
		BaseURL:       cfg.CoreURL,
		InspectPath:   cfg.CoreInspectPath,
		TelemetryPath: cfg.CoreTelemetryPath,
		HealthPath:    cfg.CoreHealthPath,
		Token:         cfg.CoreToken,
	})
	if err != nil {
		fail(err)
	}
	application, err := httpserver.New(cfg, core)
	if err != nil {
		fail(err)
	}

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           application.Handler(),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 * 1024,
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("adapter shutdown failed", "error", err)
		}
	}()

	logger.Info("CheeseWAF adapter listening", "address", cfg.ListenAddr, "core", safeCoreTarget(cfg.CoreURL), "fail_mode", cfg.FailMode)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fail(err)
	}
}

func safeCoreTarget(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<invalid>"
	}
	return parsed.Scheme + "://" + parsed.Host
}

func fail(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "adapterd: %v\n", err)
	os.Exit(1)
}
