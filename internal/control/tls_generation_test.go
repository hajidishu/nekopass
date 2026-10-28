package control

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestCertificateSettingsIdentity(t *testing.T) {
	base := DefaultTunnelTLS()
	base.ServerName = "node.example.test"
	base.ACMEEmail = "ops@example.test"
	base.DNSCredentials = map[string]string{"api_token": "fixture-token"}

	certificateChanges := []struct {
		name   string
		change func(*TunnelTLSConfig)
	}{
		{"server name", func(v *TunnelTLSConfig) { v.ServerName = "other.example.test" }},
		{"certificate mode", func(v *TunnelTLSConfig) { v.CertificateMode = "acme_http" }},
		{"certificate", func(v *TunnelTLSConfig) { v.Certificate = "certificate" }},
		{"private key", func(v *TunnelTLSConfig) { v.PrivateKey = "private-key" }},
		{"root CA", func(v *TunnelTLSConfig) { v.RootCA = "root-ca" }},
		{"ACME email", func(v *TunnelTLSConfig) { v.ACMEEmail = "other@example.test" }},
		{"ACME directory", func(v *TunnelTLSConfig) { v.ACMEDirectory = "https://acme.example.test/directory" }},
		{"ACME root CA", func(v *TunnelTLSConfig) { v.ACMERootCA = "acme-root-ca" }},
		{"HTTP challenge port", func(v *TunnelTLSConfig) { v.HTTPChallengePort++ }},
		{"DNS provider", func(v *TunnelTLSConfig) { v.DNSProvider = "alidns" }},
		{"DNS credentials", func(v *TunnelTLSConfig) { v.DNSCredentials = map[string]string{"api_token": "other-fixture-token"} }},
	}
	for _, tc := range certificateChanges {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			changed.DNSCredentials = map[string]string{"api_token": "fixture-token"}
			tc.change(&changed)
			if reflect.DeepEqual(changed.certificateSettings(), base.certificateSettings()) {
				t.Fatal("certificate-relevant change did not alter identity")
			}
		})
	}

	transportChanges := []struct {
		name   string
		change func(*TunnelTLSConfig)
	}{
		{"QUIC padding", func(v *TunnelTLSConfig) { v.QUICPadding.Enabled = !v.QUICPadding.Enabled }},
		{"raw TLS padding", func(v *TunnelTLSConfig) { v.PaddingEnabled = !v.PaddingEnabled }},
		{"raw TLS padding scheme", func(v *TunnelTLSConfig) { v.PaddingScheme = []string{"stop=8"} }},
		{"client SNI", func(v *TunnelTLSConfig) { v.ClientSNI = "client.example.test" }},
		{"fingerprint", func(v *TunnelTLSConfig) { v.Fingerprint = "chrome" }},
		{"Host", func(v *TunnelTLSConfig) { v.Host = "cdn.example.test" }},
		{"fallback URL", func(v *TunnelTLSConfig) { v.FallbackURL = "https://www.example.test" }},
		{"path", func(v *TunnelTLSConfig) { v.Path = "/other" }},
		{"public port", func(v *TunnelTLSConfig) { v.PublicPort = 443 }},
		{"pool size", func(v *TunnelTLSConfig) { v.PoolSize++ }},
		{"stream window", func(v *TunnelTLSConfig) { v.StreamWindowMiB++ }},
		{"connection window", func(v *TunnelTLSConfig) { v.ConnectionWindowMiB++ }},
		{"max streams", func(v *TunnelTLSConfig) { v.MaxStreams++ }},
		{"site title", func(v *TunnelTLSConfig) { v.SiteTitle = "other" }},
	}
	for _, tc := range transportChanges {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			changed.DNSCredentials = map[string]string{"api_token": "fixture-token"}
			tc.change(&changed)
			if !reflect.DeepEqual(changed.certificateSettings(), base.certificateSettings()) {
				t.Fatal("transport-only change altered certificate identity")
			}
		})
	}
}

func TestPrepareNodeTLSKeepsCertificateGenerationForTransportChanges(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		status string
		expiry *time.Time
	}{
		{name: "pending issuance", status: "pending"},
		{name: "renewal window", status: "ready", expiry: timePtr(time.Now().Add(20 * 24 * time.Hour))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := insertTLSGenerationNode(t, f, tc.status, tc.expiry)
			defer f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id)

			for _, change := range []struct {
				name string
				edit func(*TunnelTLSConfig)
			}{
				{"QUIC padding", func(v *TunnelTLSConfig) {
					v.QUICPadding.Enabled = true
					v.QUICPadding.MaxPadding = 512
					v.QUICPadding.BurstBytes = 4096
					v.QUICPadding.BytesPerSecond = 2048
				}},
				{"raw TLS padding", func(v *TunnelTLSConfig) { v.PaddingEnabled = true; v.PaddingScheme = nil }},
				{"Host and pool", func(v *TunnelTLSConfig) { v.Host = "cdn.example.test"; v.PoolSize = 4 }},
			} {
				t.Run(change.name, func(t *testing.T) {
					var oldGeneration int64
					var raw []byte
					if err := f.p.QueryRow(ctx, "SELECT tls_config,tls_generation FROM nodes WHERE id=$1", id).Scan(&raw, &oldGeneration); err != nil {
						t.Fatal(err)
					}
					cfg := DefaultTunnelTLS()
					if err := json.Unmarshal(raw, &cfg); err != nil {
						t.Fatal(err)
					}
					change.edit(&cfg)
					tx, err := f.p.BeginTx(ctx, pgx.TxOptions{})
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(ctx)
					input := generationTestNodeInput(cfg)
					if err = prepareNodeTLS(ctx, tx, id, &input); err != nil {
						t.Fatal(err)
					}
					var gotGeneration int64
					if err = tx.QueryRow(ctx, "SELECT tls_generation FROM nodes WHERE id=$1", id).Scan(&gotGeneration); err != nil {
						t.Fatal(err)
					}
					if gotGeneration != oldGeneration {
						t.Fatalf("transport change advanced certificate generation: got %d, want %d", gotGeneration, oldGeneration)
					}
					if err = checkOldCertificateJob(ctx, tx, id, oldGeneration, true); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestPrepareNodeTLSRejectsOldCertificateGeneration(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	cert, key, _, err := SelfSignedTunnelCertificate("node.example.test")
	if err != nil {
		t.Fatal(err)
	}

	id := insertTLSGenerationNode(t, f, "pending", nil)
	defer f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id)

	certificateChanges := []struct {
		name string
		edit func(*TunnelTLSConfig)
	}{
		{"SNI", func(v *TunnelTLSConfig) { v.ServerName = "other.example.test" }},
		{"certificate mode", func(v *TunnelTLSConfig) { v.CertificateMode = "acme_http" }},
		{"ACME email", func(v *TunnelTLSConfig) { v.ACMEEmail = "other@example.test" }},
		{"ACME directory", func(v *TunnelTLSConfig) { v.ACMEDirectory = "https://acme.example.test/directory" }},
		{"ACME trust root", func(v *TunnelTLSConfig) { v.ACMERootCA = cert }},
		{"root CA", func(v *TunnelTLSConfig) { v.RootCA = cert }},
		{"HTTP challenge port", func(v *TunnelTLSConfig) { v.HTTPChallengePort = 8080 }},
		{"DNS provider", func(v *TunnelTLSConfig) { v.DNSProvider = "alidns" }},
		{"DNS credentials", func(v *TunnelTLSConfig) { v.DNSCredentials = map[string]string{"api_token": "fixture-another-token"} }},
		{"imported certificate", func(v *TunnelTLSConfig) { v.Certificate = cert }},
		{"imported private key", func(v *TunnelTLSConfig) { v.PrivateKey = key }},
	}
	for _, change := range certificateChanges {
		t.Run(change.name, func(t *testing.T) {
			var oldGeneration int64
			var raw []byte
			if err := f.p.QueryRow(ctx, "SELECT tls_config,tls_generation FROM nodes WHERE id=$1", id).Scan(&raw, &oldGeneration); err != nil {
				t.Fatal(err)
			}
			cfg := DefaultTunnelTLS()
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			change.edit(&cfg)
			tx, err := f.p.BeginTx(ctx, pgx.TxOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			input := generationTestNodeInput(cfg)
			if err = prepareNodeTLS(ctx, tx, id, &input); err != nil {
				t.Fatal(err)
			}
			var gotGeneration int64
			if err = tx.QueryRow(ctx, "SELECT tls_generation FROM nodes WHERE id=$1", id).Scan(&gotGeneration); err != nil {
				t.Fatal(err)
			}
			if gotGeneration != oldGeneration+1 {
				t.Fatalf("certificate change did not advance generation: got %d, want %d", gotGeneration, oldGeneration+1)
			}
			if err = checkOldCertificateJob(ctx, tx, id, oldGeneration, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func insertTLSGenerationNode(t *testing.T, f *securityFixture, status string, expiry *time.Time) int64 {
	t.Helper()
	ctx := context.Background()
	cfg := DefaultTunnelTLS()
	cfg.ServerName = "node.example.test"
	cfg.CertificateMode = "acme_dns"
	cfg.DNSProvider = "cloudflare"
	cfg.ACMEEmail = "ops@example.test"
	cfg.DNSCredentials = map[string]string{"api_token": "fixture-token"}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	err = f.p.QueryRow(ctx, `INSERT INTO nodes(name,token_hash,tls_config,tls_status,tls_not_after,tls_generation,tls_certificate,tls_private_key)
VALUES($1,$2,$3,$4,$5,7,CASE WHEN $5::timestamptz IS NULL THEN '' ELSE 'fixture-certificate' END,CASE WHEN $5::timestamptz IS NULL THEN '' ELSE 'fixture-private-key' END) RETURNING id`, Secret(), Hash(Secret()), raw, status, expiry).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func generationTestNodeInput(cfg TunnelTLSConfig) NodeInput {
	return NodeInput{
		TLS: &cfg, TunnelProtocol: "tls_h3", TunnelExitEnabled: true,
		TunnelListenPort: 24443, TunnelPublicHost: "node.example.test",
	}
}

func checkOldCertificateJob(ctx context.Context, tx pgx.Tx, id, generation int64, wantAccepted bool) error {
	tag, err := tx.Exec(ctx, "UPDATE nodes SET tls_status='ready' WHERE id=$1 AND tls_generation=$2", id, generation)
	if err != nil {
		return err
	}
	want := int64(0)
	if wantAccepted {
		want = 1
	}
	if tag.RowsAffected() != want {
		return fmt.Errorf("old ACME generation accepted=%t; rows affected %d, want %d", wantAccepted, tag.RowsAffected(), want)
	}
	return nil
}

func timePtr(v time.Time) *time.Time { return &v }
