package control

import (
	"errors"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
)

// Keep validation messages useful while preventing transport/SQL errors from
// returning connection details, database values or credentials to a client.
func publicOperationError(err error) string {
	var sqlError *pgconn.PgError
	var connectError *pgconn.ConnectError
	var parseError *pgconn.ParseConfigError
	var networkError net.Error
	if errors.As(err, &sqlError) || errors.As(err, &connectError) || errors.As(err, &parseError) || errors.As(err, &networkError) {
		return "操作失败：请检查资源约束或稍后重试"
	}
	return err.Error()
}
