package control

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	acmelog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
	"github.com/go-acme/lego/v4/registration"
	"github.com/jackc/pgx/v5"
)

// Provider errors may contain URLs or credentials. Report only our own sanitized
// statuses; don't let third-party loggers write raw request/error content.
func init() { acmelog.Logger = log.New(io.Discard, "", 0) }

type acmeUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }

func (s *Server) RunCertificateClock(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	next := map[int64]time.Time{}
	delays := map[int64]time.Duration{}
	seenGen := map[int64]int64{}
	for {
		rows, err := s.Pool.Query(ctx, `SELECT id,tls_config,tls_generation FROM nodes WHERE enabled AND tunnel_exit_enabled AND tunnel_protocol IN ('tls_tcp','tls_h2','dtls_udp') AND tls_config->>'certificate_mode' IN ('acme_dns','acme_http') AND (tls_status IN ('pending','error') OR tls_not_after<now()+interval '30 days') ORDER BY id LIMIT 100`)
		if err == nil {
			type job struct {
				id, generation int64
				config         []byte
			}
			var jobs []job
			for rows.Next() {
				var j job
				if rows.Scan(&j.id, &j.config, &j.generation) == nil {
					jobs = append(jobs, j)
				}
			}
			rows.Close()
			for _, j := range jobs {
				if ctx.Err() != nil {
					return
				}
				if seenGen[j.id] == j.generation && time.Now().Before(next[j.id]) {
					continue
				}
				seenGen[j.id] = j.generation
				cfg := DefaultTunnelTLS()
				if json.Unmarshal(j.config, &cfg) != nil {
					continue
				}
				err = s.issueNodeCertificate(ctx, j.id, j.generation, cfg)
				if err != nil {
					delay := delays[j.id]
					if delay == 0 {
						delay = time.Minute
					} else {
						delay = min(delay*2, 30*time.Minute)
					}
					delays[j.id] = delay
					next[j.id] = time.Now().Add(delay)
					_, _ = s.Pool.Exec(ctx, "UPDATE nodes SET tls_status='error',tls_error='自动申请失败，请检查域名、验证端口或 DNS 凭据' WHERE id=$1 AND tls_generation=$2", j.id, j.generation)
					slog.Warn("node certificate issuance failed", "node_id", j.id, "error_type", fmt.Sprintf("%T", err))
				} else {
					delete(next, j.id)
					delete(delays, j.id)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) issueNodeCertificate(ctx context.Context, node, generation int64, cfg TunnelTLSConfig) error {
	conn, err := pgx.ConnectConfig(ctx, s.Pool.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	var locked bool
	if err = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", int64(2100000000)+node).Scan(&locked); err != nil || !locked {
		return errors.New("certificate job already active")
	}
	user, err := s.acmeAccount(ctx, node, cfg)
	if err != nil {
		return err
	}
	options := lego.NewConfig(user)
	options.CADirURL = cfg.ACMEDirectory
	options.Certificate.KeyType = certcrypto.EC256
	options.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	if cfg.ACMERootCA != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(cfg.ACMERootCA)) {
			return errors.New("invalid ACME trust root")
		}
		options.HTTPClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	}
	client, err := lego.NewClient(options)
	if err != nil {
		return err
	}
	client.Challenge.Remove(challenge.TLSALPN01)
	if cfg.CertificateMode == "acme_http" {
		client.Challenge.Remove(challenge.DNS01)
		if err = client.Challenge.SetHTTP01Provider(&nodeHTTPChallenge{server: s, node: node, generation: generation, ctx: ctx}); err != nil {
			return err
		}
	} else {
		client.Challenge.Remove(challenge.HTTP01)
		provider, err := dnsChallengeProvider(cfg)
		if err != nil {
			return err
		}
		if err = client.Challenge.SetDNS01Provider(provider); err != nil {
			return err
		}
	}
	if user.registration == nil {
		user.registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return err
		}
		data, _ := json.Marshal(user.registration)
		if _, err = s.Pool.Exec(ctx, "UPDATE node_acme_accounts SET registration=$2 WHERE node_id=$1", node, data); err != nil {
			return err
		}
	}
	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{cfg.ServerName}, Bundle: true})
	if err != nil {
		return err
	}
	until, err := validateTunnelCertificate(cfg.ServerName, string(resource.Certificate), string(resource.PrivateKey))
	if err != nil {
		return err
	}
	tx, err := s.ruleTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE nodes SET tls_certificate=$3,tls_private_key=$4,tls_ca=$6,tls_status='ready',tls_error='',tls_not_after=$5,config_revision=(SELECT value+1 FROM revision WHERE id=1) WHERE id=$1 AND tls_generation=$2", node, generation, string(resource.Certificate), string(resource.PrivateKey), until, cfg.RootCA)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("certificate configuration changed")
	}
	return finishRules(ctx, tx)
}

func (s *Server) acmeAccount(ctx context.Context, node int64, cfg TunnelTLSConfig) (*acmeUser, error) {
	u := &acmeUser{email: cfg.ACMEEmail}
	var directory, email, key string
	var data []byte
	err := s.Pool.QueryRow(ctx, "SELECT directory_url,email,private_key,registration FROM node_acme_accounts WHERE node_id=$1", node).Scan(&directory, &email, &key, &data)
	if err == nil && directory == cfg.ACMEDirectory && email == cfg.ACMEEmail {
		block, _ := pem.Decode([]byte(key))
		if block == nil {
			return nil, errors.New("invalid ACME account key")
		}
		u.key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if string(data) != "{}" {
			if err = json.Unmarshal(data, &u.registration); err != nil {
				return nil, err
			}
		}
		return u, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	u.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(u.key)
	if err != nil {
		return nil, err
	}
	key = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	_, err = s.Pool.Exec(ctx, "INSERT INTO node_acme_accounts(node_id,directory_url,email,private_key) VALUES($1,$2,$3,$4) ON CONFLICT(node_id) DO UPDATE SET directory_url=$2,email=$3,private_key=$4,registration='{}'", node, cfg.ACMEDirectory, cfg.ACMEEmail, key)
	return u, err
}

func dnsChallengeProvider(cfg TunnelTLSConfig) (challenge.Provider, error) {
	values := cfg.DNSCredentials
	switch cfg.DNSProvider {
	case "cloudflare":
		c := cloudflare.NewDefaultConfig()
		c.AuthToken = values["api_token"]
		c.ZoneToken = values["zone_token"]
		return cloudflare.NewDNSProviderConfig(c)
	case "alidns":
		c := alidns.NewDefaultConfig()
		c.APIKey = values["access_key_id"]
		c.SecretKey = values["access_key_secret"]
		c.RegionID = "cn-hangzhou"
		return alidns.NewDNSProviderConfig(c)
	case "dnspod":
		c := dnspod.NewDefaultConfig()
		c.LoginToken = values["login_token"]
		return dnspod.NewDNSProviderConfig(c)
	default:
		return nil, errors.New("unsupported DNS provider")
	}
}

type nodeHTTPChallenge struct {
	server           *Server
	node, generation int64
	ctx              context.Context
}

func (p *nodeHTTPChallenge) Present(domain, token, keyAuthorization string) error {
	ctx := p.ctx
	tx, err := p.server.ruleTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var current int64
	var configured string
	if err = tx.QueryRow(ctx, "SELECT tls_generation,tls_config->>'server_name' FROM nodes WHERE id=$1", p.node).Scan(&current, &configured); err != nil {
		return err
	}
	if current != p.generation || domain != configured {
		return errors.New("certificate challenge not authorized")
	}
	var revision int64
	if err = tx.QueryRow(ctx, "SELECT value+1 FROM revision WHERE id=1").Scan(&revision); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO node_acme_challenges(node_id,domain,token,key_authorization,expires_at,revision) VALUES($1,$2,$3,$4,now()+interval '10 minutes',$5) ON CONFLICT(node_id,token) DO UPDATE SET key_authorization=$4,expires_at=now()+interval '10 minutes',revision=$5", p.node, domain, token, keyAuthorization, revision)
	if err != nil {
		return err
	}
	if err = finishRules(ctx, tx); err != nil {
		return err
	}
	deadline := time.NewTimer(40 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("exit node did not expose HTTP-01 validation port")
		case <-ticker.C:
			var ack int64
			if err = p.server.Pool.QueryRow(ctx, "SELECT acme_ack FROM nodes WHERE id=$1", p.node).Scan(&ack); err == nil && ack >= revision {
				return nil
			}
		}
	}
}
func (p *nodeHTTPChallenge) CleanUp(domain, token, keyAuthorization string) error {
	_, err := p.server.Pool.Exec(p.ctx, "DELETE FROM node_acme_challenges WHERE node_id=$1 AND domain=$2 AND token=$3 AND key_authorization=$4", p.node, domain, token, keyAuthorization)
	return err
}
