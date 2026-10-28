ALTER TABLE nodes ADD COLUMN random_config jsonb NOT NULL DEFAULT '{"cipher":"chacha20-poly1305","key":""}';
ALTER TABLE nodes DROP CONSTRAINT nodes_tunnel_protocol_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_tunnel_protocol_check CHECK(tunnel_protocol IN ('plain_tcp','tls_tcp','plain_h2','tls_h2','plain_udp','dtls_udp','random_tcp','random_h2'));
INSERT INTO schema_version VALUES(31);
