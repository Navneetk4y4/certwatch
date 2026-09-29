package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// Test databases.
//
// These tests run against a REAL PostgreSQL. There is no mock, and that is
// deliberate: the entire tenancy guarantee is row-level security, which is a
// database behaviour. A mock store would pass every test in this file while
// the product leaked every row, because the thing under test is Postgres's
// policy engine and not our Go code.
//
//	make db-up    provision roles + database
//	go test ./internal/store/

const (
	appDSN      = "postgres://certwatch_app:certwatch_dev_password_not_for_production@localhost:5432/%s"
	migratorDSN = "postgres://certwatch_migrator:certwatch_dev_password_not_for_production@localhost:5432/%s"
	adminDSN    = "postgres://localhost:5432/postgres"
	adminOnDB   = "postgres://localhost:5432/%s"
)

func dsnFor(tmpl, db string) string {
	if v := os.Getenv("CERTWATCH_TEST_DSN_TEMPLATE"); v != "" {
		tmpl = v
	}
	return fmt.Sprintf(tmpl, db)
}

// newTestDB creates a throwaway database, migrates it, and returns an app-role
// Store plus a migrator-role pool for the privileged assertions.
func newTestDB(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()

	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Skipf("no PostgreSQL available (%v). Run: make db-up", err)
	}
	defer admin.Close()
	if err := admin.Ping(ctx); err != nil {
		t.Skipf("PostgreSQL not reachable (%v). Run: make db-up", err)
	}

	name := fmt.Sprintf("certwatch_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create a test database (%v). Run: make db-up", err)
	}
	t.Cleanup(func() {
		a, err := pgxpool.New(context.Background(), adminDSN)
		if err != nil {
			return
		}
		defer a.Close()
		_, _ = a.Exec(context.Background(),
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1", name)
		_, _ = a.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})

	// Hand the database AND its public schema to the migrator. The schema
	// chown must be done by the CURRENT owner (the admin connection), not by
	// the migrator — it does not own the schema yet, which is the point.
	if _, err := admin.Exec(ctx, fmt.Sprintf(
		"ALTER DATABASE %s OWNER TO certwatch_migrator", name)); err != nil {
		t.Fatalf("chown database: %v", err)
	}
	adminOnNew, err := pgxpool.New(ctx, dsnFor(adminOnDB, name))
	if err != nil {
		t.Fatalf("admin pool on new db: %v", err)
	}
	if _, err := adminOnNew.Exec(ctx,
		"ALTER SCHEMA public OWNER TO certwatch_migrator"); err != nil {
		adminOnNew.Close()
		t.Fatalf("chown schema: %v", err)
	}
	adminOnNew.Close()

	mig, err := pgxpool.New(ctx, dsnFor(migratorDSN, name))
	if err != nil {
		t.Fatalf("migrator pool: %v", err)
	}
	t.Cleanup(mig.Close)
	if _, err := Migrate(ctx, mig); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, f := range []string{"grants.sql"} {
		b, err := os.ReadFile("bootstrap/" + f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := mig.Exec(ctx, string(b)); err != nil {
			t.Fatalf("apply %s: %v", f, err)
		}
	}

	st, err := Open(ctx, Config{DSN: dsnFor(appDSN, name)}, safelog.Discard())
	if err != nil {
		t.Fatalf("open as app role: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.VerifyRoleIsConstrained(ctx); err != nil {
		t.Fatalf("the app role is not constrained: %v", err)
	}
	return st, mig
}

// makeTenant inserts an organization using the migrator pool. Creating a
// tenant is a privileged, pre-tenancy act: there is no tenant to scope it to
// yet. In production this is the signup path.
func makeTenant(t *testing.T, mig *pgxpool.Pool, name string) tenancy.Tenant {
	t.Helper()
	var id string
	err := mig.QueryRow(context.Background(),
		`SELECT create_organization($1)::text`, name).Scan(&id)
	if err != nil {
		t.Fatalf("create tenant %s: %v", name, err)
	}
	return tenancy.Tenant(id)
}

func ctxFor(tn tenancy.Tenant) context.Context {
	return tenancy.WithTenant(context.Background(), tn)
}
