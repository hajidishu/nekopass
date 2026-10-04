ALTER TABLE plans ADD COLUMN purchase_limit integer NOT NULL DEFAULT 0
 CHECK(purchase_limit BETWEEN 0 AND 1000000);
INSERT INTO schema_version VALUES(10);
