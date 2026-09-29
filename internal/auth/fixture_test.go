package auth

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// Real PostgreSQL, real RLS. The session model is half database policy, so a
// mocked store would prove nothing about the thing being tested.

const (
	appDSN      = "postgres://certwatch_app:certwatch_dev_password_not_for_production@localhost:5432/%s"
	migratorDSN = "postgres://certwatch_migrator:certwatch_dev_password_not_for_production@localhost:5432/%s"
	adminDSN    = "postgres://localhost:5432/postgres"
	adminOnDB   = "postgres://localhost:5432/%s"
)

type fixture struct {
	st    *store.Store
	mig   *pgxpool.Pool
	mgr   *Manager
	clock time.Time

	tenantA, tenantB tenancy.Tenant
	userA, userB     string
}

func newAuthFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()

	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Skipf("no PostgreSQL (%v). Run: make db-up", err)
	}
	defer admin.Close()
	if err := admin.Ping(ctx); err != nil {
		t.Skipf("PostgreSQL unreachable (%v). Run: make db-up", err)
	}
	name := fmt.Sprintf("certwatch_auth_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create test database (%v). Run: make db-up", err)
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

	if _, err := admin.Exec(ctx, fmt.Sprintf(
		"ALTER DATABASE %s OWNER TO certwatch_migrator", name)); err != nil {
		t.Fatal(err)
	}
	an, err := pgxpool.New(ctx, fmt.Sprintf(adminOnDB, name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := an.Exec(ctx, "ALTER SCHEMA public OWNER TO certwatch_migrator"); err != nil {
		an.Close()
		t.Fatal(err)
	}
	an.Close()

	mig, err := pgxpool.New(ctx, fmt.Sprintf(migratorDSN, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mig.Close)
	if _, err := store.Migrate(ctx, mig); err != nil {
		t.Fatal(err)
	}
	grants, err := os.ReadFile("../store/bootstrap/grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mig.Exec(ctx, string(grants)); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(ctx, store.Config{DSN: fmt.Sprintf(appDSN, name)}, safelog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.VerifyRoleIsConstrained(ctx); err != nil {
		t.Fatal(err)
	}

	f := &fixture{st: st, mig: mig, clock: time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)}
	f.mgr = NewManager(st, func() time.Time { return f.clock })

	f.tenantA = f.mkTenant(t, "tenant-a")
	f.tenantB = f.mkTenant(t, "tenant-b")
	f.userA = f.mkUser(t, f.tenantA, "a@tenant-a.test", tenancy.RoleAdmin)
	f.userB = f.mkUser(t, f.tenantB, "b@tenant-b.test", tenancy.RoleAdmin)
	return f
}

func (f *fixture) mkTenant(t *testing.T, name string) tenancy.Tenant {
	t.Helper()
	var id string
	if err := f.mig.QueryRow(context.Background(),
		`SELECT create_organization($1)::text`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return tenancy.Tenant(id)
}

func (f *fixture) mkUser(t *testing.T, tn tenancy.Tenant, email string, role tenancy.Role) string {
	t.Helper()
	var id string
	ctx := tenancy.WithTenant(context.Background(), tn)
	err := f.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx,
			`INSERT INTO users (tenant_id, email, role) VALUES ($1::uuid,$2,$3::user_role)
			 RETURNING id::text`, tn.String(), email, string(role)).Scan(&id)
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// login issues a session as if OIDC had just succeeded.
func (f *fixture) login(tn tenancy.Tenant, userID string, role tenancy.Role) (string, Session, error) {
	ctx := tenancy.WithTenant(context.Background(), tn)
	// Keep the stored role and the session role consistent: Lookup reads the
	// role from users, so a test that asks for operator must get operator.
	if err := f.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, e := tx.Conn().Exec(ctx,
			`UPDATE users SET role = $2::user_role WHERE id = $1::uuid`, userID, string(role))
		return e
	}); err != nil {
		return "", Session{}, err
	}
	return f.mgr.Create(ctx, userID, "user@example.test", role, "go-test", "")
}
