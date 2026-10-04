package control

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPublicDatabaseErrorsDoNotDiscloseValues(t *testing.T) {
	secret := "fixture-" + strings.Repeat("private", 3)
	err := fmt.Errorf("save failed: %w", &pgconn.PgError{Code: "23505", Message: secret, Detail: secret})
	if strings.Contains(publicOperationError(err), secret) {
		t.Fatal("database details returned to client")
	}
	validation := errors.New("规则数量已达上限")
	if publicOperationError(validation) != validation.Error() {
		t.Fatal("validation message was lost")
	}
}
