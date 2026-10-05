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
	var conn net.Conn
	var version uint16
	var alpn string
	var exporter []byte
	var err error
	if cfg.Fingerprint == "" || cfg.Fingerprint == "off" {
		c := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
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
	if version != tls.VersionTLS13 || alpn != "h2" {
		conn.Close()
		return nil, nil, errors.New("TLS 1.3 and h2 must be negotiated")
	}
	return conn, exporter, nil
}
