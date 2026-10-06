package tunnel

import "testing"

func TestChoicesAndLegacyCompatibility(t *testing.T) {
	for _, mode := range []string{"plain_tcp", "tls_tcp", "plain_h2", "tls_h2"} {
		transport, security := Split(mode)
		got, err := Compose(transport, security)
		if err != nil || got != mode {
			t.Fatal(mode, got, err)
		}
	}
	for _, input := range [][2]string{{"raw_tcp", ""}, {"h2", "unknown"}, {"ws", "tls"}, {"tls_h2", "none"}} {
		if _, err := Compose(input[0], input[1]); err == nil {
			t.Fatal("invalid choice accepted", input)
		}
	}
	if MinimumVersion("tls_tcp") != 13 || MinimumVersion("plain_h2") != 13 || MinimumVersion("plain_tcp") != 6 || MinimumVersion("tls_h2") != 11 {
		t.Fatal("legacy version compatibility changed")
	}
}
