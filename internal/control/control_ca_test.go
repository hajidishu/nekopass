package control

import (
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
