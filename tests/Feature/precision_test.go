package feature_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	hedatabase "github.com/arandu-io/hesape/database"
	pgxconnector "github.com/arandu-io/hesape/database/connectors/pgx"
	"github.com/arandu-io/hesape/database/migrations"

	impersonate "github.com/hyz-is/arandu-impersonate"
)

// A database migrated before the framework's default time precision was
// microseconds holds the visits' instants in whole seconds, and the last
// migration widens them in place. On SQLite there is nothing to widen, and
// every other test of this suite applies it there.

// impersonationsTable is the table the module owns.
const impersonationsTable = "impersonations"

// instants are the date-time columns of the table.
var instants = []string{"started_at", "expires_at", "closed_at", "created_at", "updated_at"}

func TestTheLastMigrationWidensTheImpersonations(t *testing.T) {
	all := (&impersonate.Module{}).Migrations()
	widen, ok := all[len(all)-1].(migrations.WidenTimePrecision)
	if !ok || widen.GetName() != "20261020_0001_widen_impersonations_time_precision" ||
		len(widen.Tables) != 1 || widen.Tables[0] != impersonationsTable {
		t.Fatalf("the last migration is %s, want the widening of the impersonations", all[len(all)-1].GetName())
	}
}

func TestTheImpersonationsAreWidenedOnPostgres(t *testing.T) {
	dsn := os.Getenv("ARANDU_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("no server: set ARANDU_TEST_POSTGRES_DSN")
	}
	ctx := context.Background()
	suffix := make([]byte, 8)
	_, _ = rand.Read(suffix)
	schema := "impersonate_" + hex.EncodeToString(suffix)

	admin, err := sql.Open(pgxconnector.PostgresConnector{}.DriverName(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	pool, err := sql.Open(pgxconnector.PostgresConnector{}.DriverName(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	conn := hedatabase.ForMigrations(hedatabase.NewConnection(pool, schema, "", map[string]any{"driver": "pgsql", "name": "impersonate-test"}))
	all := (&impersonate.Module{}).Migrations()
	for _, migration := range all[:len(all)-1] {
		if err := migration.Up(ctx, conn); err != nil {
			t.Fatalf("applying %s: %v", migration.GetName(), err)
		}
	}
	// The shape a release before the widening left on a database migrated
	// while the default was whole seconds, with one visit already in it.
	for _, column := range instants {
		if _, err := pool.ExecContext(ctx, `ALTER TABLE `+impersonationsTable+` ALTER COLUMN `+column+` TYPE timestamp(0) without time zone`); err != nil {
			t.Fatal(err)
		}
	}
	insert := `INSERT INTO ` + impersonationsTable + `
		(id, tenant_id, actor_id, target_id, acting, status, started_at, expires_at, closed_at, end_reason, created_at, updated_at, reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if _, err := pool.ExecContext(ctx, insert, "visit-1", tenant, "op-1", "ana", 1, "open",
		at, at.Add(30*time.Minute), at, "", at, at, ""); err != nil {
		t.Fatal(err)
	}

	if err := all[len(all)-1].Up(ctx, conn); err != nil {
		t.Fatalf("widening: %v", err)
	}
	var narrow int
	if err := pool.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND data_type LIKE 'timestamp%' AND datetime_precision < 6`).Scan(&narrow); err != nil {
		t.Fatal(err)
	}
	if narrow != 0 {
		t.Fatalf("%d date-time columns are still in seconds after the widening", narrow)
	}
	// New connections, as a deploy has after it migrates: one that prepared a
	// statement over the narrow columns is refused its cached plan.
	pool.SetMaxIdleConns(0)
	pool.SetMaxIdleConns(2)

	var started time.Time
	if err := pool.QueryRowContext(ctx, `SELECT started_at FROM `+impersonationsTable+` WHERE id = $1`, "visit-1").Scan(&started); err != nil {
		t.Fatal(err)
	}
	if !started.UTC().Equal(at) {
		t.Fatalf("the visit from before the widening started at %s, want %s", started.UTC(), at)
	}
	// A visit written after the widening keeps its instants to the microsecond.
	precise := at.Add(time.Second + 123456*time.Microsecond)
	if _, err := pool.ExecContext(ctx, insert, "visit-2", tenant, "op-2", "ana", 1, "open",
		precise, precise.Add(30*time.Minute), precise, "", precise, precise, ""); err != nil {
		t.Fatal(err)
	}
	for _, column := range instants {
		var read time.Time
		if err := pool.QueryRowContext(ctx, `SELECT `+column+` FROM `+impersonationsTable+` WHERE id = $1`, "visit-2").Scan(&read); err != nil {
			t.Fatal(err)
		}
		want := precise
		if column == "expires_at" {
			want = precise.Add(30 * time.Minute)
		}
		if !read.UTC().Equal(want) {
			t.Errorf("%s reads back %s, want %s", column, read.UTC(), want)
		}
	}
	if reversible, ok := all[len(all)-1].(migrations.ReversibleMigration); !ok {
		t.Fatal("the widening cannot be rolled back")
	} else if err := reversible.Down(ctx, conn); err != nil {
		t.Fatalf("rolling the widening back: %v", err)
	}
}
