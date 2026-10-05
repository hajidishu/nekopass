ALTER TABLE rules DROP CONSTRAINT rules_proxy_accept_check;
ALTER TABLE rules ADD CONSTRAINT rules_proxy_accept_check CHECK(proxy_accept IN ('off','v1','v2','auto'));
INSERT INTO schema_version VALUES(14);
