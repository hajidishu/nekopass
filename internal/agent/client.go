package agent

import (
	"context"
	"errors"
	"log/slog"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func Run(ctx context.Context, e *Engine, server, token string) error {
	if token == "" || server == "" {
		return errors.New("server and node token required")
	}
	origin := server
	server, err := e.redirectedControlEndpoint(origin)
	if err != nil {
		return err
	}
	c, err := e.state.Config()
	if err != nil {
		return err
	}
	if err = e.Apply(c); err != nil {
		return err
	}
	go e.collectProbe(ctx)
	for ctx.Err() == nil {
		target, transport, err := controlEndpoint(server)
		if err != nil {
			return err
		}
		conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(transport), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20), grpc.MaxCallSendMsgSize(16<<20)))
		if err != nil {
			return err
		}
		err = runSession(ctx, e, pb.NewControlClient(conn), token, server)
		conn.Close()
		if ctx.Err() != nil {
			break
		}
		var redirect *controlRedirect
		if errors.As(err, &redirect) {
			if err := e.saveControlEndpoint(origin, redirect.endpoint); err != nil {
				return err
			}
			server = redirect.endpoint
			slog.Info("control endpoint changed; reconnecting", "server", server)
			continue
		}
		slog.Warn("control connection interrupted; retaining configuration and finite allowance", "error", err)
		// Persist usage even while disconnected.
		if _, err = e.Report(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}
func runSession(parent context.Context, e *Engine, client pb.ControlClient, token, server string) error {
	ctx, cancel := context.WithCancel(metadata.AppendToOutgoingContext(parent, "authorization", "Bearer "+token))
	defer cancel()
	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	for {
		report, err := e.Report()
		if err != nil {
			return err
		}
		// Cancel an unresponsive stream rather than trusting TCP keepalive indefinitely.
		watchdog := time.AfterFunc(8*time.Second, cancel)
		if err = stream.Send(report); err != nil {
			watchdog.Stop()
			return err
		}
		config, err := stream.Recv()
		watchdog.Stop()
		if err != nil {
			return err
		}
		if err = e.Apply(config); err != nil {
			return err
		}
		if config.ControlEndpoint != "" && config.ControlEndpoint != server {
			if _, _, err := controlEndpoint(config.ControlEndpoint); err != nil {
				return err
			}
			return &controlRedirect{endpoint: config.ControlEndpoint}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
