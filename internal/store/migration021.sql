ALTER TABLE rules ADD COLUMN protocol text NOT NULL DEFAULT 'tcp' CHECK(protocol IN ('tcp','udp','tcp_udp'));
ALTER TABLE rules DROP CONSTRAINT rules_node_id_listen_port_key;
CREATE TABLE rule_ports (
 node_id bigint NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 protocol text NOT NULL CHECK(protocol IN ('tcp','udp')),
 listen_port integer NOT NULL,
 rule_id bigint NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
 PRIMARY KEY(node_id,protocol,listen_port)
);
CREATE INDEX rule_ports_owner ON rule_ports(rule_id);
INSERT INTO rule_ports SELECT node_id,'tcp',listen_port,id FROM rules;
CREATE FUNCTION reserve_rule_ports() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 DELETE FROM rule_ports WHERE rule_id=NEW.id;
 IF NEW.protocol IN ('tcp','tcp_udp') THEN
  INSERT INTO rule_ports VALUES(NEW.node_id,'tcp',NEW.listen_port,NEW.id);
 END IF;
 IF NEW.protocol IN ('udp','tcp_udp') THEN
  INSERT INTO rule_ports VALUES(NEW.node_id,'udp',NEW.listen_port,NEW.id);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER reserve_rule_ports AFTER INSERT OR UPDATE OF node_id,listen_port,protocol ON rules
FOR EACH ROW EXECUTE FUNCTION reserve_rule_ports();
ALTER TABLE nodes DROP CONSTRAINT nodes_tunnel_protocol_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_tunnel_protocol_check CHECK(tunnel_protocol IN ('plain_tcp','tls_tcp','plain_h2','tls_h2','plain_udp','dtls_udp'));
ALTER TABLE nodes ADD COLUMN udp_idle_timeout_seconds integer NOT NULL DEFAULT 60 CHECK(udp_idle_timeout_seconds BETWEEN 10 AND 3600);
INSERT INTO schema_version VALUES(21);
