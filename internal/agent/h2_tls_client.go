package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	pb "github.com/nekopass/nekopass/internal/protocol"
	utls "github.com/refraction-networking/utls"
)

func dialTunnelTLS(ctx context.Context, raw net.Conn, cfg *pb.TLSClientConfig, roots *x509.CertPool) (net.Conn, []byte, error) {
	return dialTunnelTLSProtocol(ctx, raw, cfg, roots, true)
}

func dialTunnelTLSProtocol(ctx context.Context, raw net.Conn, cfg *pb.TLSClientConfig, roots *x509.CertPool, h2 bool) (net.Conn, []byte, error) {
	protocols := []string{"h2"}
	if !h2 {
		protocols = []string{"http/1.1"}
	}
	var conn net.Conn
	var version uint16
	var alpn string
	var exporter []byte
	var err error
	if cfg.Fingerprint == "" || cfg.Fingerprint == "off" {
		c := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: protocols})
		conn = c
		if err = c.HandshakeContext(ctx); err == nil {
			state := c.ConnectionState()
			version, alpn = state.Version, state.NegotiatedProtocol
			exporter, err = state.ExportKeyingMaterial(exporterLabel, nil, 32)
		}
	} else {
		profile := utls.HelloChrome_Auto
		if cfg.Fingerprint == "firefox" {
			profile = utls.HelloFirefox_Auto
		} else if cfg.Fingerprint != "chrome" {
			raw.Close()
			return nil, nil, errors.New("unsupported uTLS fingerprint")
		}
		c := utls.UClient(raw, &utls.Config{RootCAs: roots, ServerName: cfg.ServerName, MinVersion: utls.VersionTLS13, MaxVersion: utls.VersionTLS13}, profile)
		conn = c
		if err = c.BuildHandshakeState(); err == nil {
			for _, extension := range c.Extensions {
				if info, ok := extension.(*utls.RenegotiationInfoExtension); ok {
					info.Renegotiation = utls.RenegotiateNever
				}
			}
			err = c.HandshakeContext(ctx)
		}
		if err == nil {
			state := c.ConnectionState()
			version, alpn = state.Version, state.NegotiatedProtocol
			exporter, err = state.ExportKeyingMaterial(exporterLabel, nil, 32)
		}
	}
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if version != tls.VersionTLS13 || h2 && alpn != "h2" || !h2 && alpn != "" && alpn != "http/1.1" {
		conn.Close()
		return nil, nil, errors.New("TLS version or negotiated transport mismatch")
	}
	return conn, exporter, nil
}
