ALTER TABLE nodes ADD COLUMN allow_direct boolean NOT NULL DEFAULT true;
ALTER TABLE nodes ADD COLUMN tunnel_exit_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE nodes ADD COLUMN tunnel_protocol text NOT NULL DEFAULT 'plain_tcp' CHECK(tunnel_protocol='plain_tcp');
ALTER TABLE nodes ADD COLUMN tunnel_listen_host text NOT NULL DEFAULT '0.0.0.0';
ALTER TABLE nodes ADD COLUMN tunnel_listen_port integer NOT NULL DEFAULT 0 CHECK(tunnel_listen_port=0 OR tunnel_listen_port BETWEEN 1024 AND 65535);
ALTER TABLE nodes ADD COLUMN tunnel_public_host text NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN egress_node_id bigint REFERENCES nodes(id);
CREATE INDEX rules_egress_node_id ON rules(egress_node_id);
CREATE TABLE node_tunnel_links (
 ingress_node_id bigint NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 egress_node_id bigint NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 token text NOT NULL,
 PRIMARY KEY(ingress_node_id,egress_node_id),
 CHECK(ingress_node_id<>egress_node_id)
);
UPDATE revision SET value=value+1;
INSERT INTO schema_version VALUES(8);
