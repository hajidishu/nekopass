ALTER TABLE nodes DROP CONSTRAINT nodes_tunnel_protocol_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_tunnel_protocol_check CHECK(tunnel_protocol IN ('plain_tcp','tls_tcp','plain_h2','tls_h2','plain_udp','dtls_udp','random_tcp','random_h2','random_udp','tls_h3'));
INSERT INTO schema_version VALUES(33);
