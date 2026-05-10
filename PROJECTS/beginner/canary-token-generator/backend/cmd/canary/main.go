// ©AngelaMos | 2026
// main.go

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/config"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/core"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/health"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/server"
)

const drainDelay = 5 * time.Second

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		slog.Error("application error", "error", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	logger := setupLogger(cfg.Log)
	slog.SetDefault(logger)
	logger.Info("starting canary-token-generator",
		"version", cfg.App.Version,
		"environment", cfg.App.Environment,
	)

	var telemetry *core.Telemetry
	if cfg.Otel.Enabled {
		if t, telErr := core.NewTelemetry(ctx, cfg.Otel, cfg.App); telErr != nil {
			logger.Warn("telemetry init failed", "error", telErr)
		} else {
			telemetry = t
		}
	}

	db, err := core.NewDatabase(ctx, cfg.Database)
	if err != nil {
		return err
	}
	logger.Info("database connected")

	rdb, err := core.NewRedis(ctx, cfg.Redis)
	if err != nil {
		return err
	}
	logger.Info("redis connected")

	healthH := health.NewHandler(db, rdb)

	srv := server.New(server.Config{
		ServerConfig:  cfg.Server,
		HealthHandler: healthH,
		Logger:        logger,
	})
	r := srv.Router()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger(logger))
	r.Use(
		middleware.NewRateLimiter(rdb.Client, middleware.RateLimitConfig{
			Limit:    middleware.PerMinute(cfg.RateLimit.Requests, cfg.RateLimit.Burst),
			FailOpen: true,
		}).Handler,
	)
	r.Use(middleware.SecurityHeaders(cfg.App.Environment == "production"))
	r.Use(middleware.CORS(cfg.CORS))

	healthH.RegisterRoutes(r)

	r.Route("/api", func(_ chi.Router) {
	})

	errChan := make(chan error, 1)
	go func() { errChan <- srv.Start() }()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(),
		cfg.Server.ShutdownTimeout+drainDelay+5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx, drainDelay); err != nil {
		logger.Error("server shutdown error", "error", err)
	}
	if telemetry != nil {
		_ = telemetry.Shutdown(shutdownCtx)
	}
	if err := rdb.Close(); err != nil {
		logger.Error("redis close error", "error", err)
	}
	if err := db.Close(); err != nil {
		logger.Error("database close error", "error", err)
	}

	logger.Info("application stopped")
	return nil
}

func setupLogger(cfg config.LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}
