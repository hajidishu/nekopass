-- Preserve both existing modes and allow transport/security combinations.
ALTER TABLE nodes DROP CONSTRAINT nodes_tunnel_protocol_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_tunnel_protocol_check
 CHECK(tunnel_protocol IN ('plain_tcp','tls_tcp','plain_h2','tls_h2'));
INSERT INTO schema_version VALUES(16);
