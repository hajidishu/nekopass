package tunnel

import "testing"

func TestChoicesAndLegacyCompatibility(t *testing.T) {
	for _, mode := range []string{"plain_tcp", "tls_tcp", "plain_h2", "tls_h2", "plain_udp", "dtls_udp", "random_tcp", "random_h2", "random_udp", "tls_h3"} {
		transport, security := Split(mode)
		got, err := Compose(transport, security)
		if err != nil || got != mode {
			t.Fatal(mode, got, err)
		}
	}
	for _, input := range [][2]string{{"raw_tcp", ""}, {"h2", "unknown"}, {"ws", "tls"}, {"tls_h2", "none"}, {"h3", "none"}, {"h3", "random"}} {
		if _, err := Compose(input[0], input[1]); err == nil {
			t.Fatal("invalid choice accepted", input)
		}
	}
	if MinimumVersion("tls_tcp") != 13 || MinimumVersion("plain_h2") != 13 || MinimumVersion("plain_tcp") != 6 || MinimumVersion("tls_h2") != 11 {
		t.Fatal("legacy version compatibility changed")
	}
	if MinimumVersion("plain_udp") != 17 || MinimumVersion("dtls_udp") != 17 {
		t.Fatal("native UDP allows agents with directionless authentication")
	}
	if MinimumVersion("tls_h3") != 28 {
		t.Fatal("HTTP/3 permits unsupported agents")
	}
	if MinimumVersion("random_udp") != 27 {
		t.Fatal("UDP encryption permits unsupported agents")
	}
	if MinimumVersion("random_tcp") != 26 || MinimumVersion("random_h2") != 26 {
		t.Fatal("random encryption permits unsupported agents")
	}
}
