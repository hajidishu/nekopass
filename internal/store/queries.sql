-- name: FindUserByName :one
SELECT * FROM users WHERE username = $1;

-- name: FindUser :one
SELECT * FROM users WHERE id = $1;

-- name: FindSession :one
SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
WHERE s.token_hash=$1 AND s.expires_at>now();

-- name: DeleteSession :exec
DELETE FROM sessions WHERE token_hash=$1;

-- name: FindNodeByToken :one
SELECT * FROM nodes WHERE token_hash=$1;

-- name: BumpRevision :exec
UPDATE revision SET value=value+1 WHERE id=1;
