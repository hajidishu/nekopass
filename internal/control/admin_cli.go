package control

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// These operations are local CLI commands, never HTTP endpoints.
func RandomAdministratorPassword() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func ResetAdministratorPassword(ctx context.Context, p *pgxpool.Pool, username string) (string, string, error) {
	tx, err := p.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT id,username,enabled FROM users WHERE is_admin AND ($1='' OR username=$1) ORDER BY id FOR UPDATE", username)
	if err != nil {
		return "", "", err
	}
	var id int64
	var name string
	var enabled bool
	count := 0
	for rows.Next() {
		if err = rows.Scan(&id, &name, &enabled); err != nil {
			rows.Close()
			return "", "", err
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", "", err
	}
	if count == 0 {
		return "", "", errors.New("管理员不存在")
	}
	if count != 1 {
		return "", "", errors.New("存在多个管理员，请使用 -admin-name 指定账号")
	}
	if !enabled {
		return "", "", errors.New("管理员已停用，密码重置不会重新启用账号")
	}
	password, err := RandomAdministratorPassword()
	if err != nil {
		return "", "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	if _, err = tx.Exec(ctx, "UPDATE users SET password_hash=$2 WHERE id=$1", id, string(hash)); err != nil {
		return "", "", err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM sessions WHERE user_id=$1", id); err != nil {
		return "", "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", "", err
	}
	return name, password, nil
}

func InitializeInstallationSettings(ctx context.Context, p *pgxpool.Pool, v SystemSettings) error {
	if err := validateSettings(v); err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = p.Exec(ctx, "UPDATE site_settings SET config=$1 WHERE id=1", data)
	return err
}
