-- Retain original IDs and historical usage on TCP; start each new UDP rule at zero.
CREATE TEMP TABLE nekopass_combined_rules ON COMMIT DROP AS
 SELECT * FROM rules WHERE protocol='tcp_udp';

UPDATE rules SET protocol='tcp',config_revision=(SELECT value+1 FROM revision WHERE id=1)
 WHERE protocol='tcp_udp';

WITH added AS (
 INSERT INTO rules(user_id,node_id,listen_host,listen_port,target_host,target_port,enabled,
  name,group_id,targets,balance,speed_mbps,ip_limit,connection_limit,
  proxy_accept,proxy_send,proxy_trusted_cidrs,traffic_baseline,config_revision,egress_node_id,protocol)
 SELECT user_id,node_id,listen_host,listen_port,target_host,target_port,enabled,
  name,group_id,targets,balance,speed_mbps,ip_limit,connection_limit,
  'off','off','[]'::jsonb,0,(SELECT value+1 FROM revision WHERE id=1),egress_node_id,'udp'
 FROM nekopass_combined_rules
 RETURNING id,node_id,user_id
)
INSERT INTO rule_usage(node_id,rule_id,user_id,traffic)
 SELECT node_id,id,user_id,0 FROM added;

ALTER TABLE rules DROP CONSTRAINT rules_protocol_check;
ALTER TABLE rules ADD CONSTRAINT rules_protocol_check CHECK(protocol IN ('tcp','udp'));
CREATE OR REPLACE FUNCTION reserve_rule_ports() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 DELETE FROM rule_ports WHERE rule_id=NEW.id;
 INSERT INTO rule_ports VALUES(NEW.node_id,NEW.protocol,NEW.listen_port,NEW.id);
 RETURN NEW;
END $$;

UPDATE revision SET value=value+1;
INSERT INTO schema_version VALUES(22);
