package control

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestPublicControlTrustRejectsMixedMaterials(t *testing.T) {
	cert, key, _, err := SelfSignedTunnelCertificate("agent.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err = publicCertificatePEM(cert); err != nil {
		t.Fatal(err)
	}
	v := defaultSettings()
	v.PanelURL = "http://panel.example.test:8080"
	v.AgentHost = "2001:db8::1"
	command := installCommand(v, "fixture-node-key", cert, false)
	if !strings.Contains(command, "--server '[2001:db8::1]:9443'") || !strings.Contains(command, shellQuote(base64.StdEncoding.EncodeToString([]byte(cert)))) || strings.Contains(command, key) || strings.Contains(command, "\n") {
		t.Fatal("embedded public control CA or IPv6 endpoint invalid")
	}
	for _, value := range []string{"unrelated text\n" + cert, cert + "unrelated text", key + cert, cert + key} {
		if publicCertificatePEM(value) == nil {
			t.Fatal("non-public material accepted")
		}
	}
}

func TestACMERootHasSameSizeBoundAsOtherCertificates(t *testing.T) {
	cert, _, _, err := SelfSignedTunnelCertificate("ca.example.test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultTunnelTLS()
	cfg.ACMERootCA = strings.Repeat(cert, 65536/len(cert)+1)
	if err = cfg.normalize(); err == nil || err.Error() != "证书材料过大" {
		t.Fatal("ACME root size was not bounded")
	}
}
