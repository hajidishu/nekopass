ALTER TABLE registration_captchas ADD COLUMN purpose text NOT NULL DEFAULT 'registration' CHECK(purpose IN ('registration','ticket'));
ALTER TABLE registration_captchas ADD COLUMN user_id bigint REFERENCES users(id) ON DELETE CASCADE;
CREATE TABLE announcements (
 id bigserial PRIMARY KEY, title text NOT NULL, content text NOT NULL,
 published boolean NOT NULL DEFAULT true, sort_order integer NOT NULL DEFAULT 0, legacy boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX announcements_legacy ON announcements(legacy) WHERE legacy;
INSERT INTO announcements(title,content,legacy) SELECT '站点公告',announcement,true FROM site_settings WHERE id=1 AND btrim(announcement)<>'';
CREATE TABLE tickets (
 id bigserial PRIMARY KEY, user_id bigint NOT NULL REFERENCES users(id),
 title text NOT NULL, priority text NOT NULL CHECK(priority IN ('low','medium','high')),
 status text NOT NULL DEFAULT 'waiting_staff' CHECK(status IN ('waiting_staff','waiting_user','closed')),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tickets_user_time ON tickets(user_id,updated_at DESC,id DESC);
CREATE INDEX tickets_status ON tickets(status,updated_at DESC);
CREATE TABLE ticket_messages (
 id bigserial PRIMARY KEY, ticket_id bigint NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
 sender_id bigint NOT NULL REFERENCES users(id), sender_is_staff boolean NOT NULL,
 content text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ticket_messages_thread ON ticket_messages(ticket_id,id);
INSERT INTO schema_version VALUES(19);
