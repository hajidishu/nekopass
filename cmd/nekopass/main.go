package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nekopass/nekopass/internal/control"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/release"
	"github.com/nekopass/nekopass/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"runtime"
)

func main() {
	if err := run(); err != nil {
		slog.Error("control stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	mode := flag.String("mode", "serve", "serve, migrate, bootstrap, reset-admin, init-settings")
	adminName := flag.String("admin-name", "", "administrator username for local CLI commands")
	randomPassword := flag.Bool("random-password", false, "generate the initial administrator password")
	httpAddr := flag.String("http", ":8080", "HTTP listen address (TLS terminates at your reverse proxy)")
	grpcAddr := flag.String("grpc", ":9443", "agent control listen address")
	web := flag.String("web", "/opt/nekopass/web", "built frontend directory")
	showVersion := flag.Bool("version", false, "show build version")
	flag.Parse()
	if *showVersion {
		fmt.Printf("nekopass %s %s/%s\n", release.Version, runtime.GOOS, runtime.GOARCH)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	p, err := store.Open(ctx, os.Getenv("NEKOPASS_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer p.Close()
	if *mode == "migrate" {
		return store.Migrate(ctx, p)
	}
	if *mode == "bootstrap" {
		username := *adminName
		if username == "" {
			username = os.Getenv("NEKOPASS_ADMIN_USERNAME")
		}
		if *randomPassword {
			if username == "" {
				username = "admin"
			}
			password, generateErr := control.RandomAdministratorPassword()
			if generateErr != nil {
				return generateErr
			}
			if err = control.Bootstrap(ctx, p, username, password); err != nil {
				return err
			}
			fmt.Printf("管理员账号：%s\n管理员密码：%s\n", username, password)
			return nil
		}
		return control.Bootstrap(ctx, p, username, os.Getenv("NEKOPASS_ADMIN_PASSWORD"))
	}
	if *mode == "reset-admin" {
		username, password, resetErr := control.ResetAdministratorPassword(ctx, p, *adminName)
		if resetErr != nil {
			return resetErr
		}
		fmt.Printf("管理员账号：%s\n新的管理员密码：%s\n旧登录会话已失效。\n", username, password)
		return nil
	}
	if *mode == "init-settings" {
		var settings control.SystemSettings
		decoder := json.NewDecoder(io.LimitReader(os.Stdin, 16384))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&settings); err != nil {
			return errors.New("invalid installation settings")
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("invalid installation settings")
		}
		return control.InitializeInstallationSettings(ctx, p, settings)
	}
	if *mode != "serve" {
		return errors.New("invalid mode")
	}
	if err = store.CheckSchema(ctx, p); err != nil {
		return err
	}
	server := control.New(p)
	updateDir := os.Getenv("NEKOPASS_PANEL_UPDATE_DIR")
	if updateDir == "" {
		updateDir = "/var/lib/nekopass"
	}
	server.SetPanelUpdateDirectory(updateDir)
	go server.RunSubscriptionClock(ctx)
	go server.RunCertificateClock(ctx)
	if trusted, exists := os.LookupEnv("NEKOPASS_TRUSTED_PROXIES"); exists {
		if err = server.SetTrustedProxies(trusted); err != nil {
			return err
		}
	}
	httpServer := &http.Server{Addr: *httpAddr, Handler: server.Handler(http.FileServer(http.Dir(*web))), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	grpcOptions := []grpc.ServerOption{grpc.MaxRecvMsgSize(16 << 20), grpc.MaxSendMsgSize(16 << 20), grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second})}
	// Legacy certificate variables apply only to the separate Agent listener.
	// New installations may terminate gRPC TLS at Nginx as well.
	certFile, keyFile := os.Getenv("NEKOPASS_GRPC_TLS_CERT"), os.Getenv("NEKOPASS_GRPC_TLS_KEY")
	if certFile == "" && keyFile == "" {
		certFile, keyFile = os.Getenv("NEKOPASS_TLS_CERT"), os.Getenv("NEKOPASS_TLS_KEY")
	}
	ln, agentCredentials, err := server.StartAgentListener(ctx, *grpcAddr, certFile, keyFile)
	if err != nil {
		return err
	}
	defer ln.Close()
	grpcOptions = append(grpcOptions, grpc.Creds(agentCredentials))
	grpcServer := grpc.NewServer(grpcOptions...)
	pb.RegisterControlServer(grpcServer, &control.StreamServer{Server: server})
	errCh := make(chan error, 2)
	go func() { errCh <- grpcServer.Serve(ln) }()
	go func() { errCh <- httpServer.ListenAndServe() }()
	slog.Info("control ready", "http", *httpAddr, "grpc", ln.Addr().String())
	select {
	case <-ctx.Done():
	case err = <-errCh:
	}
	grpcServer.Stop()
	shutdown, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	_ = httpServer.Shutdown(shutdown)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}
