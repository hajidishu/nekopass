package store

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestStartupSchemaVersionMatchesLatestMigration(t *testing.T) {
	files, err := filepath.Glob("migration*.sql")
	if err != nil || len(files) == 0 {
		t.Fatal("cannot locate schema migrations", err)
	}
	latest := 1
	for _, file := range files {
		version, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(file, "migration"), ".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if version > latest {
			latest = version
		}
	}
	if CurrentSchemaVersion != latest {
		t.Fatalf("startup expects schema %d but latest migration is %d", CurrentSchemaVersion, latest)
	}
}
