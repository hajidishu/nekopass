package control

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

type TunnelTLSConfig struct {
	ServerName          string            `json:"server_name"`
	ClientSNI           string            `json:"client_sni"`
	Fingerprint         string            `json:"fingerprint"`
	CertificateMode     string            `json:"certificate_mode"`
	Certificate         string            `json:"certificate"`
	PrivateKey          string            `json:"private_key"`
	RootCA              string            `json:"root_ca"`
	Path                string            `json:"path"`
	PublicPort          int               `json:"public_port"`
	PoolSize            int               `json:"pool_size"`
	StreamWindowMiB     int               `json:"stream_window_mib"`
	ConnectionWindowMiB int               `json:"connection_window_mib"`
	MaxStreams          int               `json:"max_streams"`
	SiteTitle           string            `json:"site_title"`
	ACMEEmail           string            `json:"acme_email"`
	ACMEDirectory       string            `json:"acme_directory"`
	ACMERootCA          string            `json:"acme_root_ca"`
	HTTPChallengePort   int               `json:"http_challenge_port"`
	DNSProvider         string            `json:"dns_provider"`
	DNSCredentials      map[string]string `json:"dns_credentials"`
}

func DefaultTunnelTLS() TunnelTLSConfig {
	return TunnelTLSConfig{Fingerprint: "chrome", CertificateMode: "self_signed", Path: "/api/stream", PoolSize: 2,
		StreamWindowMiB: 16, ConnectionWindowMiB: 64, MaxStreams: 256, SiteTitle: "Welcome", HTTPChallengePort: 80,
		ACMEDirectory: "https://acme-v02.api.letsencrypt.org/directory", DNSCredentials: map[string]string{}}
}

func (v *TunnelTLSConfig) normalize() error {
	d := DefaultTunnelTLS()
	if v.Fingerprint == "" {
		v.Fingerprint = d.Fingerprint
	}
	if v.CertificateMode == "" {
		v.CertificateMode = d.CertificateMode
	}
	if v.Path == "" {
		v.Path = d.Path
	}
	if v.PoolSize == 0 {
		v.PoolSize = d.PoolSize
	}
	if v.StreamWindowMiB == 0 {
		v.StreamWindowMiB = d.StreamWindowMiB
	}
	if v.ConnectionWindowMiB == 0 {
		v.ConnectionWindowMiB = d.ConnectionWindowMiB
	}
	if v.MaxStreams == 0 {
		v.MaxStreams = d.MaxStreams
	}
	if v.SiteTitle == "" {
		v.SiteTitle = d.SiteTitle
	}
	if v.HTTPChallengePort == 0 {
		v.HTTPChallengePort = d.HTTPChallengePort
	}
	if v.ACMEDirectory == "" {
		v.ACMEDirectory = d.ACMEDirectory
	}
	if v.DNSCredentials == nil {
		v.DNSCredentials = map[string]string{}
	}
	v.ServerName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v.ServerName), "."))
	v.ClientSNI = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v.ClientSNI), "."))
	if v.Fingerprint != "chrome" && v.Fingerprint != "firefox" {
		return errors.New("请选择 Chrome 或 Firefox 指纹")
	}
	if v.CertificateMode != "self_signed" && v.CertificateMode != "import" && v.CertificateMode != "acme_dns" && v.CertificateMode != "acme_http" {
		return errors.New("证书模式无效")
	}
	for _, name := range []string{v.ServerName, v.ClientSNI} {
		if name != "" && (!ValidTarget(name) || net.ParseIP(name) != nil) {
			return errors.New("SNI 须为有效域名")
		}
	}
	u, err := url.ParseRequestURI(v.Path)
	if err != nil || !strings.HasPrefix(v.Path, "/") || strings.HasPrefix(v.Path, "//") || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(v.Path, "\\\r\n\x00") || len(v.Path) > 200 {
		return errors.New("隧道路径须为站点内路径，不含查询参数")
	}
	if v.PublicPort < 0 || v.PublicPort > 65535 || v.PoolSize < 1 || v.PoolSize > 8 || v.StreamWindowMiB < 1 || v.StreamWindowMiB > 64 || v.ConnectionWindowMiB < v.StreamWindowMiB || v.ConnectionWindowMiB > 256 || v.MaxStreams < 1 || v.MaxStreams > 1024 || v.HTTPChallengePort < 1 || v.HTTPChallengePort > 65535 || len(v.SiteTitle) > 200 {
		return errors.New("TLS 端口、连接池或流控参数超出范围")
	}
	if !httpsURL(v.ACMEDirectory, false) || len(v.ACMEDirectory) > 2048 || len(v.ACMEEmail) > 254 {
		return errors.New("ACME 地址或邮箱格式无效")
	}
	if len(v.DNSCredentials) > 8 {
		return errors.New("DNS 凭据参数过多")
	}
	for key, value := range v.DNSCredentials {
		if len(key) > 64 || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("DNS 凭据格式无效")
		}
	}
	if len(v.Certificate) > 65536 || len(v.PrivateKey) > 16384 || len(v.RootCA) > 65536 || len(v.ACMERootCA) > 65536 {
		return errors.New("证书材料过大")
	}
	for _, material := range []string{v.Certificate, v.RootCA, v.ACMERootCA} {
		if material != "" {
			if err := publicCertificatePEM(material); err != nil {
				return err
			}
		}
	}
	return nil
}

func publicCertificatePEM(raw string) error {
	remaining := []byte(raw)
	count := 0
	for len(strings.TrimSpace(string(remaining))) > 0 {
		if !strings.HasPrefix(strings.TrimSpace(string(remaining)), "-----BEGIN CERTIFICATE-----") {
			return errors.New("公开证书材料不能包含其他内容")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("公开证书材料不能包含私钥或其他内容")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return errors.New("公开证书无效")
		}
		remaining = rest
		count++
	}
	if count == 0 {
		return errors.New("公开证书为空")
	}
	return nil
}

// Generated only at runtime, never as source/release fixture credentials.
func SelfSignedTunnelCertificate(name string) (certificate, privateKey string, expiry time.Time, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", time.Time{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", time.Time{}, err
	}
	now := time.Now()
	expiry = now.AddDate(2, 0, 0)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: expiry,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", time.Time{}, err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})), expiry, nil
}

func validateTunnelCertificate(name, cert, key string) (time.Time, error) {
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil || len(pair.Certificate) == 0 {
		return time.Time{}, errors.New("证书与私钥无效或不匹配")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return time.Time{}, errors.New("证书无法解析")
	}
	if err = leaf.VerifyHostname(name); err != nil {
		return time.Time{}, errors.New("证书未覆盖配置的 SNI")
	}
	now := time.Now()
	if leaf.NotBefore.After(now) || !leaf.NotAfter.After(now) {
		return time.Time{}, errors.New("证书尚未生效或已过期")
	}
	return leaf.NotAfter, nil
}
