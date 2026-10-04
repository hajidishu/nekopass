package store

import (
	"context"
	_ "embed"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

//go:embed migration002.sql
var migration002 string

//go:embed migration003.sql
var migration003 string

//go:embed migration004.sql
var migration004 string

//go:embed migration005.sql
var migration005 string

//go:embed migration006.sql
var migration006 string

//go:embed migration007.sql
var migration007 string

//go:embed migration008.sql
var migration008 string

//go:embed migration009.sql
var migration009 string

//go:embed migration010.sql
var migration010 string

//go:embed migration011.sql
var migration011 string

//go:embed migration012.sql
var migration012 string

//go:embed migration013.sql
var migration013 string

func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	p, err := pgxpool.New(ctx, url)
	if err != nil {
		// pgx parsing errors may quote the entire DSN, including its password.
		return nil, errors.New("invalid PostgreSQL connection configuration; check NEKOPASS_DATABASE_URL")
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, errors.New("cannot connect to PostgreSQL; check database availability and connection configuration")
	}
	return p, nil
}

func Migrate(ctx context.Context, p *pgxpool.Pool) error {
	tx, err := p.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(734291)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, schema); err != nil {
		return err
	}
	var version int
	if err = tx.QueryRow(ctx, "SELECT max(version) FROM schema_version").Scan(&version); err != nil {
		return err
	}
	if version < 2 {
		if _, err = tx.Exec(ctx, migration002); err != nil {
			return err
		}
	}
	if version < 3 {
		if _, err = tx.Exec(ctx, migration003); err != nil {
			return err
		}
	}
	if version < 4 {
		if _, err = tx.Exec(ctx, migration004); err != nil {
			return err
		}
	}
	if version < 5 {
		if _, err = tx.Exec(ctx, migration005); err != nil {
			return err
		}
	}
	if version < 6 {
		if _, err = tx.Exec(ctx, migration006); err != nil {
			return err
		}
	}
	if version < 7 {
		if _, err = tx.Exec(ctx, migration007); err != nil {
			return err
		}
	}
	if version < 8 {
		if _, err = tx.Exec(ctx, migration008); err != nil {
			return err
		}
	}
	if version < 9 {
		if _, err = tx.Exec(ctx, migration009); err != nil {
			return err
		}
	}
	if version < 10 {
		if _, err = tx.Exec(ctx, migration010); err != nil {
			return err
		}
	}
	if version < 11 {
		if _, err = tx.Exec(ctx, migration011); err != nil {
			return err
		}
	}
	if version < 12 {
		if _, e := tx.Exec(ctx, migration012); e != nil {
			return e
		}
	}
	if version < 13 {
		if _, err = tx.Exec(ctx, migration013); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
