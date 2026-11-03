package control

import (
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
)

func encryptedWireRequired(protocol string, padding, mux bool) bool {
	return tunnel.Random(protocol) || protocol == "dtls_udp" || protocol == "tls_tcp" && padding && mux
}

func encryptedRuleSupported(rule *pb.Rule, ingress, exit int32) bool {
	return !encryptedWireRequired(rule.TunnelProtocol, rule.Tls.GetPaddingEnabled(), rule.Mux.GetEnabled()) || ingress >= pb.EncryptedTunnelVersion && exit >= pb.EncryptedTunnelVersion
}
