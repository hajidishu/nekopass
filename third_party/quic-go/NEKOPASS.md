# Nekopass QUIC dependency

Based on quic-go v0.64.1 (MIT; see LICENSE). Contains runtime Go sources; upstream examples, test credentials and integration fixtures are excluded.

Local changes: optional `Config.PacketPadding`, copied by Config.Clone; bounded connection-level adaptive padding in the existing 1-RTT packet packer; atomic counters; a size bound for a short-header packet coalesced after handshake packets. QUIC PADDING uses standard frames. TLS, authentication and congestion control remain upstream implementations.

Modified upstream files: interface.go, config.go, connection.go, packet_packer.go. Added: packet_padding.go and packet_padding_test.go. Review these changes when updating upstream.

`connection_streams.go` adds a locked count of unfinished outgoing bidirectional streams so retiring H3 pools can drain reliable tails before closing. No wire format or congestion behavior changes.
