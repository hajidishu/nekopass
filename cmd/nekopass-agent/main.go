package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/nekopass/nekopass/internal/agent"
	"github.com/nekopass/nekopass/internal/release"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	server := flag.String("server", os.Getenv("NEKOPASS_SERVER"), "control gRPC host:port")
	statePath := flag.String("state", "/var/lib/nekopass-agent/state.db", "durable state; never delete or clone between nodes")
	ca := flag.String("ca", os.Getenv("NEKOPASS_CA"), "trusted control CA certificate")
	showVersion := flag.Bool("version", false, "show build version")
	flag.Parse()
	if version != "dev" {
		release.Version = version
	}
	if *showVersion {
		fmt.Printf("nekopass-agent %s %s/%s\n", release.Version, runtime.GOOS, runtime.GOARCH)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(*statePath), 0700); err != nil {
		return err
	}
	state, err := agent.OpenState(*statePath)
	if err != nil {
		return err
	}
	defer state.Close()
	engine, err := agent.NewEngine(state, 0)
	if err != nil {
		return err
	}
	defer engine.Close()
	// The privileged updater is installed separately; Agent retains its normal user.
	if _, err := os.Stat("/etc/systemd/system/" + filepath.Base(filepath.Dir(*statePath)) + "-update.path"); err == nil {
		if err = engine.SetUpdateDirectory(filepath.Dir(*statePath)); err != nil {
			return err
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	slog.Info("agent starting", "server", *server)
	return agent.Run(ctx, engine, *server, os.Getenv("NEKOPASS_NODE_TOKEN"), *ca)
}
