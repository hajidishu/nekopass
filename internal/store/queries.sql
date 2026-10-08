-- name: FindUserByName :one
SELECT * FROM users WHERE username = $1;

-- name: FindUser :one
SELECT * FROM users WHERE id = $1;

-- name: FindSession :one
SELECT sqlc.embed(u),s.cookie_renewed_at FROM users u JOIN sessions s ON s.user_id=u.id
WHERE s.token_hash=$1 AND (s.expires_at IS NULL OR s.expires_at>now());

-- name: RenewSessionCookie :execrows
UPDATE sessions SET expires_at=NULL,cookie_renewed_at=now()
WHERE token_hash=$1 AND (expires_at IS NULL OR expires_at>now())
AND (expires_at IS NOT NULL OR cookie_renewed_at<=now()-interval '24 hours')
AND EXISTS(SELECT 1 FROM users WHERE users.id=sessions.user_id AND users.enabled);

-- name: DeleteSession :exec
DELETE FROM sessions WHERE token_hash=$1;

-- name: FindNodeByToken :one
SELECT * FROM nodes WHERE token_hash=$1;

-- name: BumpRevision :exec
UPDATE revision SET value=value+1 WHERE id=1;
