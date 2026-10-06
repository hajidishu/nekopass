package control

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
)

func prepareNodeTLS(ctx context.Context, tx pgx.Tx, id int64, input *NodeInput) error {
	old := DefaultTunnelTLS()
	var cert, key, ca, status string
	var generation int64
	var expiry *time.Time
	if id != 0 {
		var data []byte
		if err := tx.QueryRow(ctx, "SELECT tls_config,tls_certificate,tls_private_key,tls_ca,tls_status,tls_not_after,tls_generation FROM nodes WHERE id=$1", id).Scan(&data, &cert, &key, &ca, &status, &expiry, &generation); err != nil {
			return err
		}
		if err := json.Unmarshal(data, &old); err != nil {
			return err
		}
		if err := old.normalize(); err != nil {
			return err
		}
	}
	cfg := old
	if input.TLS != nil {
		cfg = *input.TLS
	}
	if cfg.ServerName == "" && tunnel.TLS(input.TunnelProtocol) && ValidTarget(input.TunnelPublicHost) {
		cfg.ServerName = input.TunnelPublicHost
	}
	if err := cfg.normalize(); err != nil {
		return err
	}
	if tunnel.TLS(input.TunnelProtocol) && input.TunnelExitEnabled {
		if cfg.ServerName == "" {
			return errors.New("TLS 出口需要 SNI 域名")
		}
		switch cfg.CertificateMode {
		case "self_signed":
			if cert == "" || cfg.ServerName != old.ServerName || old.CertificateMode != "self_signed" || expiry == nil || time.Until(*expiry) < 30*24*time.Hour {
				var until time.Time
				var err error
				cert, key, until, err = SelfSignedTunnelCertificate(cfg.ServerName)
				if err != nil {
					return err
				}
				ca = cert
				expiry = &until
			}
			status = "ready"
		case "import":
			if cfg.Certificate != "" || cfg.PrivateKey != "" {
				cert, key = cfg.Certificate, cfg.PrivateKey
			} else if old.CertificateMode != "import" {
				return errors.New("导入模式须填写证书和匹配私钥")
			}
			until, err := validateTunnelCertificate(cfg.ServerName, cert, key)
			if err != nil {
				return err
			}
			expiry = &until
			ca = cfg.RootCA
			status = "ready"
		case "acme_dns", "acme_http":
			if cfg.ACMEEmail == "" {
				return errors.New("自动申请证书须填写 ACME 邮箱")
			}
			if cfg.CertificateMode == "acme_dns" {
				if cfg.DNSProvider != "cloudflare" && cfg.DNSProvider != "alidns" && cfg.DNSProvider != "dnspod" {
					return errors.New("请选择支持的 DNS 服务商")
				}
				if len(cfg.DNSCredentials) == 0 {
					return errors.New("DNS 自动申请须填写服务商凭据")
				}
			}
			if !reflect.DeepEqual(cfg, old) || cert == "" || expiry == nil || time.Until(*expiry) < 30*24*time.Hour {
				status = "pending"
			}
		}
	}
	if !reflect.DeepEqual(cfg, old) {
		generation++
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE nodes SET tls_config=$2,tls_certificate=$3,tls_private_key=$4,tls_ca=$5,tls_status=$6,tls_not_after=$7,tls_generation=$8,tls_error='' WHERE id=$1", id, data, cert, key, ca, status, expiry, generation)
	return err
}

func appendTLSControl(ctx context.Context, tx pgx.Tx, nodeID int64, out *pb.ControlMessage) error {
	var data []byte
	var cert, key string
	if err := tx.QueryRow(ctx, "SELECT tls_config,tls_certificate,tls_private_key FROM nodes WHERE id=$1", nodeID).Scan(&data, &cert, &key); err != nil {
		return err
	}
	client := DefaultTunnelTLS()
	if err := json.Unmarshal(data, &client); err != nil {
		return err
	}
	if err := client.normalize(); err != nil {
		return err
	}
	out.Node.Tls = &pb.TLSServerConfig{ServerName: client.ServerName, Certificate: cert, PrivateKey: key, Path: client.Path,
		StreamWindowMib: int32(client.StreamWindowMiB), ConnectionWindowMib: int32(client.ConnectionWindowMiB), MaxStreams: int32(client.MaxStreams), ChallengePort: int32(client.HTTPChallengePort), SiteTitle: client.SiteTitle, Host: client.Host, FallbackUrl: client.FallbackURL}
	if !tunnel.TLS(out.Node.TunnelProtocol) {
		out.Node.Tls.Certificate = ""
		out.Node.Tls.PrivateKey = ""
		out.Node.Tls.ServerName = ""
		out.Node.Tls.Challenges = nil
	}
	rows, err := tx.Query(ctx, "SELECT domain,token,key_authorization,revision,extract(epoch FROM expires_at)::bigint FROM node_acme_challenges WHERE node_id=$1 AND expires_at>now()", nodeID)
	if err != nil {
		return err
	}
	for rows.Next() {
		v := &pb.ACMEChallenge{}
		if err = rows.Scan(&v.Domain, &v.Token, &v.KeyAuthorization, &v.Revision, &v.ExpiresUnix); err != nil {
			rows.Close()
			return err
		}
		out.Node.Tls.Challenges = append(out.Node.Tls.Challenges, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !tunnel.TLS(out.Node.TunnelProtocol) {
		out.Node.Tls.Challenges = nil
	}
	type peerKey struct {
		node int64
		mode string
	}
	cache := map[peerKey]*pb.TLSClientConfig{}
	for _, rule := range out.Rules {
		if rule.EgressNodeId == 0 {
			continue
		}
		key := peerKey{rule.EgressNodeId, rule.TunnelProtocol}
		settings := cache[key]
		if settings == nil {
			var cfgData []byte
			var root string
			if err = tx.QueryRow(ctx, "SELECT tls_config,tls_ca FROM nodes WHERE id=$1", rule.EgressNodeId).Scan(&cfgData, &root); err != nil {
				return err
			}
			exit := DefaultTunnelTLS()
			if err = json.Unmarshal(cfgData, &exit); err != nil {
				return err
			}
			if err = exit.normalize(); err != nil {
				return err
			}
			sni := exit.ServerName
			if exit.ClientSNI != "" {
				sni = exit.ClientSNI
			}
			host := exit.Host
			if host == "" {
				host = exit.ServerName
			}
			// Transport options belong to the selected exit. A dual-role node's
			// own exit configuration must not affect its connections to other exits.
			settings = &pb.TLSClientConfig{ServerName: sni, Fingerprint: exit.Fingerprint, RootCa: root, Path: exit.Path, Host: host, RequireResponseProof: true, PoolSize: int32(exit.PoolSize), StreamWindowMib: int32(exit.StreamWindowMiB), ConnectionWindowMib: int32(exit.ConnectionWindowMiB)}
			if !tunnel.TLS(rule.TunnelProtocol) {
				settings.RootCa = ""
				settings.ServerName = ""
				settings.Fingerprint = "off"
				settings.Host = exit.Host
			}
			cache[key] = settings
			if exit.PublicPort != 0 {
				for _, candidate := range out.Rules {
					if candidate.EgressNodeId == rule.EgressNodeId {
						candidate.TunnelPort = int32(exit.PublicPort)
					}
				}
			}
		}
		rule.Tls = settings
		if !tunnel.TLS(rule.TunnelProtocol) && !tunnel.H2(rule.TunnelProtocol) {
			rule.Tls = nil
		}
	}
	return nil
}
