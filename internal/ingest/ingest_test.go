package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/certwatch/certwatch/internal/enroll"
	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// Real PostgreSQL, real CA, real CSRs, real mTLS over a real TLS 1.3
// connection. Nothing here asserts that a mock returned "authenticated".

type fx struct {
	st         *store.Store
	ca         *enroll.LocalCA
	en         *enroll.Service
	svc        *Service
	clock      time.Time
	a, b       tenancy.Tenant
	srv        *httptest.Server
	serverPool *x509.CertPool
}

func newFx(t *testing.T) *fx {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, "postgres://localhost:5432/postgres")
	if err != nil {
		t.Skipf("no PostgreSQL (%v). Run: make db-up", err)
	}
	defer admin.Close()
	if err := admin.Ping(ctx); err != nil {
		t.Skipf("PostgreSQL unreachable (%v). Run: make db-up", err)
	}
	name := fmt.Sprintf("certwatch_ingest_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create test database: %v", err)
	}
	t.Cleanup(func() {
		a, e := pgxpool.New(context.Background(), "postgres://localhost:5432/postgres")
		if e != nil {
			return
		}
		defer a.Close()
		_, _ = a.Exec(context.Background(),
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1", name)
		_, _ = a.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	if _, err := admin.Exec(ctx,
		fmt.Sprintf("ALTER DATABASE %s OWNER TO certwatch_migrator", name)); err != nil {
		t.Fatal(err)
	}
	an, _ := pgxpool.New(ctx, fmt.Sprintf("postgres://localhost:5432/%s", name))
	if _, err := an.Exec(ctx, "ALTER SCHEMA public OWNER TO certwatch_migrator"); err != nil {
		an.Close()
		t.Fatal(err)
	}
	an.Close()
	mig, err := pgxpool.New(ctx, fmt.Sprintf(
		"postgres://certwatch_migrator:certwatch_dev_password_not_for_production@localhost:5432/%s", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mig.Close)
	if _, err := store.Migrate(ctx, mig); err != nil {
		t.Fatal(err)
	}
	grants, _ := os.ReadFile("../store/bootstrap/grants.sql")
	if _, err := mig.Exec(ctx, string(grants)); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, store.Config{DSN: fmt.Sprintf(
		"postgres://certwatch_app:certwatch_dev_password_not_for_production@localhost:5432/%s", name)},
		safelog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	// The test clock is anchored to REAL time, not a fixed date. Go's TLS stack
	// verifies certificate validity against the wall clock, so a client or
	// server certificate minted at an arbitrary fake instant is
	// "not yet valid" during the handshake. Tests that need to move time still
	// advance f.clock; they just start from now.
	f := &fx{st: st, clock: time.Now().UTC()}
	nowFn := func() time.Time { return f.clock }
	ca, _, err := enroll.GenerateLocalCA("certwatch test CA", f.clock)
	if err != nil {
		t.Fatal(err)
	}
	f.ca = ca
	f.en = enroll.NewService(st, ca, safelog.Discard(), nowFn)
	f.svc = NewService(st, safelog.Discard(), nowFn)

	for _, p := range []*tenancy.Tenant{&f.a, &f.b} {
		var id string
		if err := mig.QueryRow(ctx, `SELECT create_organization($1)::text`,
			fmt.Sprintf("t%d", time.Now().UnixNano())).Scan(&id); err != nil {
			t.Fatal(err)
		}
		*p = tenancy.Tenant(id)
	}
	return f
}

func (f *fx) ctx(tn tenancy.Tenant) context.Context {
	return tenancy.WithTenant(context.Background(), tn)
}

// makeCSR generates a key the test keeps — the server never sees it, which is
// the whole point of CSR-based enrolment.
func makeCSR(t *testing.T, cn string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// enrolled runs a full enrolment and returns the usable client identity.
func (f *fx) enrolled(t *testing.T, tn tenancy.Tenant, name string) (enroll.Result, *ecdsa.PrivateKey) {
	t.Helper()
	tok, _, err := f.en.MintToken(f.ctx(tn), "")
	if err != nil {
		t.Fatal(err)
	}
	csr, key := makeCSR(t, "collector")
	res, err := f.en.Enroll(context.Background(), tok, csr, name)
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	return res, key
}

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

func TestValidEnrollmentIssuesAClientCertificate(t *testing.T) {
	f := newFx(t)
	res, _ := f.enrolled(t, f.a, "collector-1")
	if res.CollectorID == "" || len(res.CertificatePEM) == 0 {
		t.Fatalf("enrolment returned nothing usable: %+v", res)
	}
	blk, _ := pem.Decode(res.CertificatePEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// CLIENT auth only. Server auth would let a collector impersonate the
	// control plane to another collector.
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			t.Error("the issued collector certificate carries serverAuth")
		}
	}
	if cert.IsCA {
		t.Error("the issued certificate is a CA")
	}
	// The CN is derived by the server from the tenant, never taken from the
	// CSR — otherwise a collector could ask for another's identity.
	if !strings.Contains(cert.Subject.CommonName, f.a.String()) {
		t.Errorf("CN = %q, want it derived from the tenant", cert.Subject.CommonName)
	}
}

// A token is single use. A replay is 409, distinct from 401, because they are
// different situations: expired means "start again", replayed means "somebody
// may have your token".
func TestEnrollmentTokenIsSingleUse(t *testing.T) {
	f := newFx(t)
	tok, _, err := f.en.MintToken(f.ctx(f.a), "")
	if err != nil {
		t.Fatal(err)
	}
	csr1, _ := makeCSR(t, "c1")
	if _, err := f.en.Enroll(context.Background(), tok, csr1, "c1"); err != nil {
		t.Fatal(err)
	}
	csr2, _ := makeCSR(t, "c2")
	_, err = f.en.Enroll(context.Background(), tok, csr2, "c2")
	if !errors.Is(err, enroll.ErrTokenUsed) {
		t.Fatalf("replay err = %v, want ErrTokenUsed (409)", err)
	}
}

func TestExpiredEnrollmentTokenIsRefused(t *testing.T) {
	f := newFx(t)
	tok, _, err := f.en.MintToken(f.ctx(f.a), "")
	if err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(enroll.TokenTTL + time.Minute)
	csr, _ := makeCSR(t, "c")
	if _, err := f.en.Enroll(context.Background(), tok, csr, "c"); !errors.Is(err, enroll.ErrTokenUnknown) {
		t.Fatalf("err = %v, want ErrTokenUnknown (401)", err)
	}
}

func TestUnknownTokenIsRefused(t *testing.T) {
	f := newFx(t)
	csr, _ := makeCSR(t, "c")
	for _, tok := range []string{"", "nope", strings.Repeat("A", 43)} {
		if _, err := f.en.Enroll(context.Background(), tok, csr, "c"); err == nil {
			t.Errorf("token %q was accepted", tok)
		}
	}
}

// A weak key must be refused rather than certified. Issuing a weak identity is
// worse than refusing to issue one.
func TestWeakKeyIsRefused(t *testing.T) {
	f := newFx(t)
	tok, _, _ := f.en.MintToken(f.ctx(f.a), "")
	key, err := rsa.GenerateKey(rand.Reader, 2048) // below the 3072 minimum
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "weak"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.en.Enroll(context.Background(), tok, csr, "weak"); !errors.Is(err, enroll.ErrWeakKey) {
		t.Fatalf("err = %v, want ErrWeakKey (422)", err)
	}
}

// A CSR whose signature does not verify is not proof of possession: anyone
// could have a certificate issued for somebody else's public key.
func TestCSRWithBrokenSignatureIsRefused(t *testing.T) {
	f := newFx(t)
	csr, _ := makeCSR(t, "c")
	tampered := append([]byte(nil), csr...)
	tampered[len(tampered)-5] ^= 0xFF // corrupt the signature
	if _, err := enroll.ValidateCSR(tampered, ""); err == nil {
		t.Fatal("a CSR with a corrupted signature was accepted")
	}
	tok, _, _ := f.en.MintToken(f.ctx(f.a), "")
	if _, err := f.en.Enroll(context.Background(), tok, tampered, "c"); err == nil {
		t.Fatal("enrolment accepted a CSR with a corrupted signature")
	}
}

func TestRevokedCertificateIsRefused(t *testing.T) {
	f := newFx(t)
	res, _ := f.enrolled(t, f.a, "c")
	blk, _ := pem.Decode(res.CertificatePEM)

	if _, err := f.en.ResolveClient(context.Background(), blk.Bytes); err != nil {
		t.Fatalf("precondition: a fresh certificate does not resolve: %v", err)
	}
	if err := f.en.Revoke(f.ctx(f.a), res.Fingerprint, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.en.ResolveClient(context.Background(), blk.Bytes); !errors.Is(err, enroll.ErrRevoked) {
		t.Fatalf("err = %v, want ErrRevoked — revocation must take effect immediately", err)
	}
}

func TestExpiredClientCertificateIsRefused(t *testing.T) {
	f := newFx(t)
	res, _ := f.enrolled(t, f.a, "c")
	blk, _ := pem.Decode(res.CertificatePEM)
	f.clock = f.clock.Add(enroll.ClientCertLifetime + time.Hour)
	if _, err := f.en.ResolveClient(context.Background(), blk.Bytes); err == nil {
		t.Fatal("an expired client certificate still resolved")
	}
}

func TestRotationAtHalfLife(t *testing.T) {
	nb := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(30 * 24 * time.Hour)
	if enroll.ShouldRotate(nb, na, nb.Add(14*24*time.Hour)) {
		t.Error("rotation triggered before half-life")
	}
	if !enroll.ShouldRotate(nb, na, nb.Add(16*24*time.Hour)) {
		t.Error("rotation did not trigger after half-life")
	}
}

func TestRotationSupersedesTheOldCertificate(t *testing.T) {
	f := newFx(t)
	res, _ := f.enrolled(t, f.a, "c")
	csr2, _ := makeCSR(t, "c")
	res2, err := f.en.Rotate(f.ctx(f.a), res.CollectorID, csr2)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Fingerprint == res.Fingerprint {
		t.Fatal("rotation returned the same certificate")
	}
	// Both resolve to the same collector; the operator revokes the old one.
	id2, err := f.en.ResolveClient(context.Background(), mustDER(t, res2.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	if id2.CollectorID != res.CollectorID {
		t.Error("rotation changed the collector identity")
	}
}

func mustDER(t *testing.T, p []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(p)
	if blk == nil {
		t.Fatal("not PEM")
	}
	return blk.Bytes
}

// ---------------------------------------------------------------------------
// INV-5 — the server does not trust the collector
// ---------------------------------------------------------------------------

func TestPrivateKeyMaterialInPayloadIsRejected(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	realKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	for _, payload := range []string{
		realKeyPEM,
		"-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBg\n-----END PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
		`{"private_key_pem":"x"}`,
		"PuTTY-User-Key-File-2: ssh-rsa",
	} {
		if got := ScanForKeyMaterial([]byte(payload)); got == "" {
			t.Errorf("key material not detected in %.40q", payload)
		}
	}
	// And a normal batch must NOT trip it — a detector that fires on
	// everything is as useless as one that never fires.
	clean, _ := json.Marshal(Batch{BatchID: "batch-0001",
		Observations: []Observation{{Address: "10.0.0.1", Port: 443,
			Fingerprint: strings.Repeat("a", 64), SubjectCN: "api.example.com"}}})
	if got := ScanForKeyMaterial(clean); got != "" {
		t.Errorf("a clean batch was flagged as key material by %s", got)
	}
}

func TestDecoderRejectsKeyMaterialBeforeParsing(t *testing.T) {
	d := &Decoder{}
	body := `{"batch_id":"batch-001x","observations":[],` +
		`"scope_digest":"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}`
	if _, err := d.Decode(strings.NewReader(body), false); !errors.Is(err, ErrKeyMaterial) {
		t.Fatalf("err = %v, want ErrKeyMaterial", err)
	}
}

// ---------------------------------------------------------------------------
// Decoder: closed schema and caps
// ---------------------------------------------------------------------------

func TestUnknownFieldIsRejected(t *testing.T) {
	d := &Decoder{}
	body := `{"batch_id":"batch-001x","observations":[],"surprise":"new"}`
	if _, err := d.Decode(strings.NewReader(body), false); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("err = %v, want ErrUnknownField. Tightening after collectors "+
			"are deployed is not possible.", err)
	}
}

func TestTooManyObservationsIsRejected(t *testing.T) {
	d := &Decoder{}
	obs := make([]Observation, MaxObservations+1)
	for i := range obs {
		obs[i] = Observation{Address: "10.0.0.1", Port: 443, Fingerprint: strings.Repeat("a", 64)}
	}
	body, _ := json.Marshal(Batch{BatchID: "batch-001x", Observations: obs})
	if _, err := d.Decode(bytes.NewReader(body), false); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

// A gzip bomb must be bounded, not OOM the process.
func TestGzipBombIsBounded(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	for i := 0; i < 64; i++ { // 64 MB of A, compresses tiny
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	zw.Close()
	if buf.Len() > MaxCompressedBytes {
		t.Skipf("fixture too large on the wire (%d)", buf.Len())
	}
	d := &Decoder{}
	_, err := d.Decode(bytes.NewReader(buf.Bytes()), true)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge — a gzip bomb must be bounded", err)
	}
}

func TestMalformedPayloadsFailSafely(t *testing.T) {
	d := &Decoder{}
	for _, body := range []string{
		"", "{", "null", "[]", `{"batch_id":5}`, "\x00\x01\x02",
		`{"batch_id":"batch-001x"}{"batch_id":"batch-002x"}`, // two values
		`{"batch_id":"short"}`,                               // too short
	} {
		if _, err := d.Decode(strings.NewReader(body), false); err == nil {
			t.Errorf("malformed payload accepted: %.30q", body)
		}
	}
}

// ---------------------------------------------------------------------------
// Ingest: tenancy, idempotency, isolation
// ---------------------------------------------------------------------------

func batch(id string, n int) Batch {
	obs := make([]Observation, n)
	for i := range obs {
		obs[i] = Observation{
			Hostname: fmt.Sprintf("h%d.example.com", i), Address: "10.0.0.1", Port: 443,
			Fingerprint: fmt.Sprintf("%064x", i+1), SubjectCN: "x",
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		}
	}
	return Batch{BatchID: id, Observations: obs}
}

func TestAcceptStoresObservations(t *testing.T) {
	f := newFx(t)
	res, _ := f.enrolled(t, f.a, "c")
	id, err := f.en.ResolveClient(context.Background(), mustDER(t, res.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	n, dup, err := f.svc.Accept(context.Background(), id, batch("batch-0001", 3))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || dup {
		t.Fatalf("accepted=%d duplicate=%v, want 3/false", n, dup)
	}
}

// INGEST-004 / P-8: a replayed batch changes NO row.
func TestReplayedBatchChangesNothing(t *testing.T) {
	f := newFx(t)
	res, _ := f.enrolled(t, f.a, "c")
	id, _ := f.en.ResolveClient(context.Background(), mustDER(t, res.CertificatePEM))

	if _, _, err := f.svc.Accept(context.Background(), id, batch("batch-0001", 5)); err != nil {
		t.Fatal(err)
	}
	countBefore := f.countObservations(t, f.a)

	for i := 0; i < 3; i++ {
		_, dup, err := f.svc.Accept(context.Background(), id, batch("batch-0001", 5))
		if err != nil {
			t.Fatal(err)
		}
		if !dup {
			t.Fatalf("replay %d was not recognised as a duplicate", i)
		}
	}
	if after := f.countObservations(t, f.a); after != countBefore {
		t.Errorf("observations %d -> %d across three replays; a retry must change no row",
			countBefore, after)
	}
}

func (f *fx) countObservations(t *testing.T, tn tenancy.Tenant) int {
	t.Helper()
	var n int
	if err := f.st.InTenantTx(f.ctx(tn), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx, `SELECT count(*) FROM observations`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// THE cross-tenant ingestion attack: a legitimately-enrolled collector for
// tenant A sends a batch claiming tenant B.
func TestCrossTenantIngestionIsRefusedAndAudited(t *testing.T) {
	f := newFx(t)
	res, _ := f.enrolled(t, f.a, "c")
	id, _ := f.en.ResolveClient(context.Background(), mustDER(t, res.CertificatePEM))

	b := batch("batch-0001", 2)
	b.TenantID = f.b.String() // claim the other tenant
	_, _, err := f.svc.Accept(context.Background(), id, b)
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("err = %v, want ErrTenantMismatch (403)", err)
	}
	// Nothing landed in B.
	if n := f.countObservations(t, f.b); n != 0 {
		t.Errorf("tenant B received %d observations from tenant A's collector", n)
	}
	// And it was audited.
	var audits int
	if err := f.st.InTenantTx(f.ctx(f.a), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE action = 'ingest.tenant_mismatch'`).Scan(&audits)
	}); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Errorf("audit events = %d, want 1 — a collector claiming another tenant "+
			"must leave a trace", audits)
	}
}

// A collector's data must never appear in another tenant.
func TestIngestedDataIsTenantIsolated(t *testing.T) {
	f := newFx(t)
	resA, _ := f.enrolled(t, f.a, "ca")
	resB, _ := f.enrolled(t, f.b, "cb")
	idA, _ := f.en.ResolveClient(context.Background(), mustDER(t, resA.CertificatePEM))
	idB, _ := f.en.ResolveClient(context.Background(), mustDER(t, resB.CertificatePEM))

	if _, _, err := f.svc.Accept(context.Background(), idA, batch("batch-000a", 4)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Accept(context.Background(), idB, batch("batch-000b", 2)); err != nil {
		t.Fatal(err)
	}
	if n := f.countObservations(t, f.a); n != 4 {
		t.Errorf("tenant A sees %d observations, want 4", n)
	}
	if n := f.countObservations(t, f.b); n != 2 {
		t.Errorf("tenant B sees %d observations, want 2", n)
	}
}

// ---------------------------------------------------------------------------
// Real mTLS
// ---------------------------------------------------------------------------

// serve starts a real TLS 1.3 server requiring a client certificate signed by
// the product CA.
//
// The SERVER certificate comes from a separate test-only CA. That is not a
// shortcut: the product CA signs client certificates exclusively — it sets
// ExtKeyUsage to clientAuth and nothing else — precisely so a collector
// identity can never be used to impersonate the control plane. Using it for
// the server here would quietly rely on the thing the design forbids.
func (f *fx) serve(t *testing.T) {
	t.Helper()
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    f.clock.Add(-time.Hour),
		NotAfter:     f.clock.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true, BasicConstraintsValid: true,
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &srvKey.PublicKey, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := x509.ParseCertificate(srvDER)
	if err != nil {
		t.Fatal(err)
	}
	f.serverPool = x509.NewCertPool()
	f.serverPool.AddCert(srvCert)

	// Clients are verified against the PRODUCT CA.
	clientPool := x509.NewCertPool()
	for _, c := range f.ca.Bundle() {
		clientPool.AddCert(c)
	}
	h := &Handler{Svc: f.svc, Enroll: f.en, Log: safelog.Discard()}
	s := httptest.NewUnstartedServer(h)
	s.TLS = ServerTLSConfig(
		tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}, clientPool)
	s.StartTLS()
	t.Cleanup(s.Close)
	f.srv = s
}

func (f *fx) client(t *testing.T, certPEM []byte, key *ecdsa.PrivateKey) *http.Client {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	cfg := ClientTLSConfig(
		tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: key},
		f.serverPool, "localhost")
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

func TestMTLSHappyPathOverARealConnection(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	res, key := f.enrolled(t, f.a, "c")
	c := f.client(t, res.CertificatePEM, key)

	body, _ := json.Marshal(batch("batch-0001", 2))
	resp, err := c.Post(f.srv.URL+"/ingest/v1/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("mTLS POST failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, b)
	}
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Errorf("negotiated TLS version = %x, want TLS 1.3", resp.TLS.Version)
	}
}

// No client certificate: the TLS handshake itself must fail. Authentication is
// a property of the connection, so there is no unauthenticated handler path.
func TestConnectionWithoutAClientCertificateIsRefused(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: f.serverPool, ServerName: "localhost", MinVersion: tls.VersionTLS13,
	}}, Timeout: 5 * time.Second}
	if _, err := c.Get(f.srv.URL + "/ingest/v1/batch"); err == nil {
		t.Fatal("a connection with no client certificate succeeded")
	}
}

// A TLS 1.2 client must be refused: the downgrade is rejected by the stack.
func TestTLS12DowngradeIsRefused(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	res, key := f.enrolled(t, f.a, "c")
	blk, _ := pem.Decode(res.CertificatePEM)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{blk.Bytes}, PrivateKey: key}},
		RootCAs:      f.serverPool, ServerName: "localhost",
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
	}}, Timeout: 5 * time.Second}
	if _, err := c.Get(f.srv.URL + "/ingest/v1/batch"); err == nil {
		t.Fatal("a TLS 1.2 client was accepted; MinVersion is not being enforced")
	}
}

// A certificate signed by a DIFFERENT CA must not be accepted, even though it
// is a structurally valid client certificate.
func TestCertificateFromAnotherCAIsRefused(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	otherCA, _, err := enroll.GenerateLocalCA("rogue CA", f.clock)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "rogue"}}, key)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	der, err := otherCA.Sign(csr, "rogue", f.clock, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		RootCAs:      f.serverPool, ServerName: "localhost", MinVersion: tls.VersionTLS13,
	}}, Timeout: 5 * time.Second}
	resp, err := c.Get(f.srv.URL + "/ingest/v1/batch")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatalf("a certificate from another CA was accepted: %d", resp.StatusCode)
		}
	}
}

// A revoked collector must stop working over a live connection, not just in
// the resolver.
func TestRevokedCollectorIsRefusedOverMTLS(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	res, key := f.enrolled(t, f.a, "c")
	c := f.client(t, res.CertificatePEM, key)
	body, _ := json.Marshal(batch("batch-0001", 1))

	resp, err := c.Post(f.srv.URL+"/ingest/v1/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("precondition: status %d", resp.StatusCode)
	}

	if err := f.en.Revoke(f.ctx(f.a), res.Fingerprint, "compromised"); err != nil {
		t.Fatal(err)
	}
	body2, _ := json.Marshal(batch("batch-0002", 1))
	resp2, err := c.Post(f.srv.URL+"/ingest/v1/batch", "application/json", bytes.NewReader(body2))
	if err != nil {
		return // connection-level refusal is also acceptable
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d after revocation, want 401", resp2.StatusCode)
	}
}

func TestHandlerRejectsKeyMaterialWith400AndCounts(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	res, key := f.enrolled(t, f.a, "c")
	c := f.client(t, res.CertificatePEM, key)

	bad := `{"batch_id":"batch-0001","observations":[],` +
		`"scope_digest":"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}`
	before := f.svc.RejectedKeyMaterial
	resp, err := c.Post(f.srv.URL+"/ingest/v1/batch", "application/json", strings.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["reason"] != "ingest.rejected_key_material" {
		t.Errorf("reason = %q, want ingest.rejected_key_material", out["reason"])
	}
	if f.svc.RejectedKeyMaterial != before+1 {
		t.Errorf("counter = %d, want %d", f.svc.RejectedKeyMaterial, before+1)
	}
}

func TestUnknownProtocolVersionIsRefusedWithAnUpgradeHint(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	res, key := f.enrolled(t, f.a, "c")
	c := f.client(t, res.CertificatePEM, key)

	req, _ := http.NewRequest("POST", f.srv.URL+"/ingest/v1/batch", strings.NewReader("{}"))
	req.Header.Set(ProtocolVersionHeader, "99")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["supported"] != ProtocolVersion || out["upgrade"] == "" {
		t.Errorf("response does not name the supported version and an upgrade path: %v", out)
	}
}

// The error body must never carry a database error, a path or a stack.
func TestErrorsDoNotLeakInternals(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	res, key := f.enrolled(t, f.a, "c")
	c := f.client(t, res.CertificatePEM, key)

	resp, err := c.Post(f.srv.URL+"/ingest/v1/batch", "application/json",
		strings.NewReader(`{"batch_id":"batch-0001","surprise":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	for _, leak := range []string{
		"SQLSTATE", "pgx", "postgres://", "certwatch_app", "/Users/", "goroutine",
		"password", "panic:",
	} {
		if strings.Contains(body, leak) {
			t.Errorf("error body leaks %q: %s", leak, body)
		}
	}
}

// A nil slice means "none", not "unknown". Sending nil as SQL NULL overrides
// the column's NOT NULL DEFAULT and fails the insert. Third occurrence of
// this exact shape in this codebase (ips_matching in internal/history was the
// second), so it gets an explicit regression test rather than a quiet fix.
func TestObservationWithNoSANsIsStored(t *testing.T) {
	f := newFx(t)
	res, _ := f.enrolled(t, f.a, "c")
	id, _ := f.en.ResolveClient(context.Background(), mustDER(t, res.CertificatePEM))

	b := Batch{BatchID: "batch-nosans", Observations: []Observation{{
		Hostname: "nosans.example.com", Address: "10.0.0.9", Port: 443,
		Fingerprint: strings.Repeat("b", 64), SubjectCN: "nosans",
		SANs: nil, // explicitly
	}}}
	n, _, err := f.svc.Accept(context.Background(), id, b)
	if err != nil {
		t.Fatalf("an observation with no SANs was rejected: %v", err)
	}
	if n != 1 {
		t.Errorf("accepted = %d, want 1", n)
	}
	// And it really is an empty array, not NULL.
	var sans []string
	if err := f.st.InTenantTx(f.ctx(f.a), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx,
			`SELECT sans FROM certificates LIMIT 1`).Scan(&sans)
	}); err != nil {
		t.Fatal(err)
	}
	if sans == nil {
		t.Error("sans stored as NULL rather than an empty array")
	}
}
