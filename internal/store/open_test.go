package store

import (
	"context"
	"strings"
	"testing"
)

func TestInvalidDatabaseConfigurationDoesNotExposePassword(t *testing.T) {
	password := "fixture-" + strings.Repeat("private", 3)
	dsn := "postgres://example:" + password + "@localhost:invalid/database"
	p, err := Open(context.Background(), dsn)
	if p != nil || err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), dsn) {
		t.Fatal("database initialization error disclosed credentials")
	}
}
