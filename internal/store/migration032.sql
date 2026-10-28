ALTER TABLE nodes DROP CONSTRAINT nodes_tunnel_protocol_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_tunnel_protocol_check CHECK(tunnel_protocol IN ('plain_tcp','tls_tcp','plain_h2','tls_h2','plain_udp','dtls_udp','random_tcp','random_h2','random_udp'));
CREATE OR REPLACE VIEW rule_outbound_routes AS
 SELECT r.id AS rule_id,n.id AS egress_node_id,1 AS weight,'active'::text AS role
 FROM rules r JOIN nodes n ON n.id=r.egress_node_id AND n.enabled AND n.tunnel_exit_enabled
 JOIN node_tunnel_links l ON l.ingress_node_id=r.node_id AND l.egress_node_id=n.id
 JOIN user_nodes a ON a.user_id=r.user_id AND a.node_id=n.id
 WHERE n.id<>r.node_id AND (r.protocol='udp' OR n.tunnel_protocol NOT IN ('plain_udp','dtls_udp','random_udp'))
 UNION ALL
 SELECT r.id,n.id,m.weight,m.role
 FROM rules r JOIN user_node_groups ug ON ug.user_id=r.user_id AND ug.group_id=r.egress_group_id
 JOIN node_groups g ON g.id=ug.group_id AND g.enabled
 JOIN node_group_members m ON m.group_id=g.id AND m.role<>'disabled'
 JOIN nodes n ON n.id=m.node_id AND n.enabled AND n.tunnel_exit_enabled AND n.id<>r.node_id
 JOIN node_tunnel_links l ON l.ingress_node_id=r.node_id AND l.egress_node_id=n.id
 JOIN user_nodes a ON a.user_id=r.user_id AND a.node_id=n.id
 WHERE r.protocol='udp' OR n.tunnel_protocol NOT IN ('plain_udp','dtls_udp','random_udp');
UPDATE revision SET value=value+1;
INSERT INTO schema_version VALUES(32);
