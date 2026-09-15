// Command importcheck enforces the four structural boundaries that cannot be
// retrofitted. It is blocking in CI.
//
//	CI-006  os/exec is absent from the collector module         (P5, threat T1)
//	CI-007  file I/O is confined to pkg/safeio and internal/spool (P3, INV-1)
//	CI-008  logging goes through pkg/safelog only                (INV-3, threat T8)
//	CI-009  cmd/certscan does not import internal/               (the OSS line)
//
// Each check is a pure import-graph or call-expression question answerable from
// the AST alone. Nothing here needs type information, so nothing here is
// approximate — an approximate security control is one that will be wrong on the
// day it matters.
//
// Usage: importcheck [-root .] [-v]
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// fileIOExceptions is the complete list of packages permitted to open files.
// It has exactly two entries and a test asserts that. Every entry on this list
// is a place the private-key boundary has to be re-argued, so growing it is a
// deliberate, reviewable act.
//
//	pkg/safeio      the boundary itself
//	internal/spool  the collector's local queue (not yet built; item 116)
var fileIOExceptions = []string{
	"pkg/safeio",
	"internal/spool",
}

// logExceptions is the only package permitted to import a logging package.
var logExceptions = []string{
	"pkg/safelog",
}

// nonCollector are build-time developer tools. They are never compiled into the
// collector binary, ship to no customer, and touch no certificate, so the
// boundaries that protect the shipped binary do not apply to them.
//
// This exclusion is narrow on purpose: it is a path prefix, not a capability,
// and anything under it is excluded from every check. Adding a path here is a
// reviewable diff, and nothing under internal/tools/ may be imported by cmd/,
// which CI-009 and Go's own internal/ rules already prevent.
var nonCollector = []string{
	"internal/tools", // build-time developer tooling
	"test",           // fixture builders and harnesses; imported only by _test.go
}

// shippedPrefixes are the trees that DO compile into the collector binary.
// A file under one of these may never import anything under nonCollector —
// otherwise the exemption above would become a hole rather than a boundary.
var shippedPrefixes = []string{"cmd", "pkg", "internal"}

// bannedFileIO are the entry points through which a file can be opened or read.
var bannedFileIO = map[string][]string{
	"os":                    {"Open", "OpenFile", "ReadFile", "ReadDir", "Create", "WriteFile"},
	"io/ioutil":             nil, // whole package
	"golang.org/x/sys/unix": {"Open", "Openat"},
}

var bannedLogImports = map[string]bool{
	"log":        true,
	"log/slog":   true,
	"log/syslog": true,
}

// bannedPrintFuncs are fmt functions that write to stdout/stderr. Formatting to
// a string (Sprintf, Errorf) is fine; writing a log line is not.
var bannedPrintFuncs = map[string]bool{
	"Print": true, "Printf": true, "Println": true,
	"Fprint": true, "Fprintf": true, "Fprintln": true,
}

type finding struct {
	check string
	pos   string
	msg   string
}

func main() {
	root := flag.String("root", ".", "module root")
	verbose := flag.Bool("v", false, "list every file scanned")
	flag.Parse()

	abs, err := filepath.Abs(*root)
	if err != nil {
		fatal(err)
	}
	var findings []finding
	scanned := 0

	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(abs, path)
		rel = filepath.ToSlash(rel)
		scanned++
		if *verbose {
			fmt.Fprintln(os.Stderr, "scanning", rel)
		}
		if inAny(rel, nonCollector) {
			return nil
		}
		findings = append(findings, checkFile(path, rel)...)
		return nil
	})
	if err != nil {
		fatal(err)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].check != findings[j].check {
			return findings[i].check < findings[j].check
		}
		return findings[i].pos < findings[j].pos
	})

	if len(findings) == 0 {
		fmt.Printf("importcheck: OK (%d files, 4 checks)\n", scanned)
		return
	}
	fmt.Fprintf(os.Stderr, "importcheck: %d violation(s) across %d files\n\n", len(findings), scanned)
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "  [%s] %s\n      %s\n", f.check, f.pos, f.msg)
	}
	fmt.Fprintln(os.Stderr, "\nThese boundaries are structural, not stylistic. See")
	fmt.Fprintln(os.Stderr, "project_1_full_development_plan.md section 3 (P3, P5) before changing them.")
	os.Exit(1)
}

func checkFile(path, rel string) []finding {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return []finding{{"parse", rel, "could not parse: " + err.Error()}}
	}
	var out []finding
	isTest := strings.HasSuffix(rel, "_test.go")

	// Which package aliases map to which import path, so we can resolve
	// selector expressions like `os.Open` even under an alias.
	aliasOf := map[string]string{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := filepath.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		aliasOf[name] = p

		// ---- CI-006: os/exec anywhere in the module, tests included.
		if p == "os/exec" {
			out = append(out, finding{"CI-006", posOf(fset, imp.Pos(), rel),
				"os/exec is imported. The collector has no command-execution path and must not gain one: " +
					"task types are a closed enum and this is what makes that claim structural (threat T1, principle P5)."})
		}

		// ---- CI-007: io/ioutil is banned outright outside the exceptions.
		if p == "io/ioutil" && !inAny(rel, fileIOExceptions) && !isTest {
			out = append(out, finding{"CI-007", posOf(fset, imp.Pos(), rel),
				"io/ioutil is imported outside pkg/safeio. All file access goes through pkg/safeio (INV-1)."})
		}

		// ---- CI-008: logging packages outside pkg/safelog.
		if bannedLogImports[p] && !inAny(rel, logExceptions) {
			out = append(out, finding{"CI-008", posOf(fset, imp.Pos(), rel),
				"a logging package is imported directly. Use pkg/safelog, whose API cannot accept a []byte (INV-3, threat T8)."})
		}

		// ---- CI-007b: shipped code must never import test scaffolding, which
		// is what keeps the nonCollector exemption a boundary and not a hole.
		if isShipped(rel) && !isTest && strings.Contains(p, "/test/") {
			out = append(out, finding{"CI-007", posOf(fset, imp.Pos(), rel),
				"shipped code imports " + p + ", which is test scaffolding exempt from the " +
					"file-I/O boundary. Importing it would route collector file access around pkg/safeio."})
		}

		// ---- CI-009: cmd/certscan must not import internal/.
		if strings.HasPrefix(rel, "cmd/certscan/") && strings.Contains(p, "/internal/") {
			out = append(out, finding{"CI-009", posOf(fset, imp.Pos(), rel),
				"cmd/certscan imports " + p + ". The open-source scanner must depend on pkg/ only, " +
					"so the OSS boundary is a property of the build rather than a policy."})
		}
	}

	// ---- CI-007 and CI-008: call-expression level.
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgPath, known := aliasOf[ident.Name]
		if !known {
			return true
		}

		if fns, banned := bannedFileIO[pkgPath]; banned {
			if fns == nil || contains(fns, sel.Sel.Name) {
				// Tests legitimately build fixture trees on disk; the boundary
				// protects the shipped binary, not the test harness.
				if !inAny(rel, fileIOExceptions) && !isTest {
					out = append(out, finding{"CI-007", posOf(fset, call.Pos(), rel),
						fmt.Sprintf("%s.%s opens a file outside pkg/safeio. "+
							"safeio is the ONLY code in the collector permitted to open a file (INV-1). "+
							"If this is genuinely necessary, it needs a new entry in fileIOExceptions and a recorded decision.",
							pkgPath, sel.Sel.Name)})
				}
			}
		}

		if pkgPath == "fmt" && bannedPrintFuncs[sel.Sel.Name] {
			// cmd/ writes its own report to stdout: that is program output, not
			// logging, and it is the point of a CLI.
			if !strings.HasPrefix(rel, "cmd/") && !inAny(rel, logExceptions) && !isTest {
				out = append(out, finding{"CI-008", posOf(fset, call.Pos(), rel),
					"fmt." + sel.Sel.Name + " writes output outside cmd/. Use pkg/safelog (INV-3)."})
			}
		}
		return true
	})

	return out
}

func posOf(fset *token.FileSet, p token.Pos, rel string) string {
	pos := fset.Position(p)
	return fmt.Sprintf("%s:%d:%d", rel, pos.Line, pos.Column)
}

func inAny(rel string, prefixes []string) bool {
	for _, p := range prefixes {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

func isShipped(rel string) bool {
	for _, p := range shippedPrefixes {
		if strings.HasPrefix(rel, p+"/") && !inAny(rel, nonCollector) {
			return true
		}
	}
	return false
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "importcheck:", err)
	os.Exit(2)
}
