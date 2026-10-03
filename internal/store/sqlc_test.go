package store

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/certwatch/certwatch/internal/store/db"
)

// Item 096. Generated code must not become a way around tenant isolation.

// A tenant-scoped generated query run on the bare pool — no tenant bound —
// must ERROR, not return rows. RLS reads current_setting(..., false), so the
// generated query inherits the same "fail loudly when unscoped" behaviour as
// hand-written SQL. sqlc generates SQL; it does not get a privileged path.
func TestGeneratedQueryOnTheBarePoolCannotBypassRLS(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "a")
	seed(t, s, a, "a.example.com")
	_, err := db.New(s.pool).DueEndpoints(context.Background(), db.DueEndpointsParams{
		Now: pgtype.Timestamptz{Time: time.Now(), Valid: true}, Lim: 10})
	if err == nil {
		t.Fatal("a generated tenant-scoped query ran with NO tenant bound and did not error")
	}
}

// Run inside tenant B's transaction, the same generated query sees only B.
func TestGeneratedQueryInATenantTxSeesOnlyThatTenant(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "a")
	b := makeTenant(t, mig, "b")
	seed(t, s, a, "a.example.com")
	seed(t, s, b, "b.example.com")
	var got []string
	if err := s.InTenantTx(ctxFor(b), func(ctx context.Context, tx *Tx) error {
		var e error
		got, e = db.New(tx.Conn()).DueEndpoints(ctx, db.DueEndpointsParams{
			Now: pgtype.Timestamptz{Time: time.Now(), Valid: true}, Lim: 50})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("tenant B's generated query returned %d endpoints, want exactly its own 1", len(got))
	}
}

// No generated code that nothing calls. Every Queries method must be invoked
// from production code outside the generated package — otherwise sqlc is
// type-checking SQL that never runs, which is coverage theatre.
func TestEveryGeneratedQueryIsUsedInProduction(t *testing.T) {
	gen, err := os.ReadFile(filepath.Join("db", "querier.go"))
	if err != nil {
		t.Fatal(err)
	}
	var methods []string
	for _, line := range strings.Split(string(gen), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "(ctx context.Context"); i > 0 && !strings.HasPrefix(line, "//") {
			methods = append(methods, line[:i])
		}
	}
	if len(methods) < 8 {
		t.Fatalf("found only %d generated methods; the scan is broken", len(methods))
	}
	used := map[string]bool{}
	root := filepath.Join("..", "..")
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") ||
			strings.Contains(path, string(filepath.Separator)+"db"+string(filepath.Separator)) {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				used[sel.Sel.Name] = true
			}
			return true
		})
		return nil
	})
	for _, m := range methods {
		if !used[m] {
			t.Errorf("generated query %s is never called from production code", m)
		}
	}
}
