package model_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
)

// PROTO-001, build item 086: the wire types are FROZEN here.
//
// These structs are shared verbatim between a collector in the field and the
// control plane's API contract. Once a collector ships, a field rename is a
// wire break that shows up as a silently-dropped value in production, not as
// a compile error. The golden file below is the contract: if a field is
// renamed, retyped or removed, this test fails and the diff says exactly what
// changed.
//
// Adding a NEW optional field is allowed and will not fail this test — that is
// the one direction that stays compatible.

func goldenPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("testdata", "wire_golden.json")
}

func sample() model.Report {
	ts := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	size := 256
	pub := true
	fp := "a43fb78433ebc310a43fb78433ebc310a43fb78433ebc310a43fb78433ebc310"
	return model.Report{
		SchemaVersion: 1,
		Tool:          "certscan",
		ToolVersion:   "0.1.0-dev",
		StartedAt:     ts,
		FinishedAt:    ts.Add(90 * time.Second),
		DurationSec:   90,
		Certificates: []model.ReportCertificate{{
			Certificate: &model.Certificate{
				Fingerprint:  fp,
				Serial:       "3e9",
				SubjectDN:    "CN=lab.internal.test,O=certwatch lab",
				SubjectCN:    "lab.internal.test",
				SANs:         []string{"lab.internal.test", "www.lab.internal.test"},
				IssuerDN:     "CN=certwatch lab issuing CA G2,O=certwatch lab",
				NotBefore:    ts.AddDate(0, -1, 0),
				NotAfter:     ts.AddDate(0, 2, 0),
				KeyAlgorithm: model.KeyAlgorithm("ECDSA"),
				KeySize:      &size,
				ParseStatus:  model.ParseOK,
			},
			SeenAt:        []string{"10.77.0.11:8443"},
			Sources:       []string{"network"},
			Resolvability: &pub,
		}},
		Endpoints: []model.ReportEndpoint{{
			Hostname:        "lab.internal.test",
			Address:         "10.77.0.11",
			Port:            8443,
			SNISent:         "lab.internal.test",
			TLSVersion:      "TLS1.3",
			LeafFingerprint: fp,
			ChainLength:     2,
		}},
	}
}

func TestWireTypesMatchTheFrozenGolden(t *testing.T) {
	got, err := json.MarshalIndent(sample(), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	p := goldenPath(t)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden updated; commit it and say in the message WHY the wire changed")
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("golden missing: %v\nGenerate it once with UPDATE_GOLDEN=1 go test ./pkg/model/", err)
	}
	if string(got)+"\n" != string(want) {
		t.Errorf("THE WIRE FORMAT CHANGED.\n\nA collector already in the field encodes the old shape. "+
			"If this change is intended, bump SchemaVersion and regenerate with UPDATE_GOLDEN=1.\n\n"+
			"got:\n%s\n\nwant:\n%s", got, want)
	}
}

// Round trip: what we encode must decode back to the same value. A field that
// marshals but does not unmarshal is a silent data-loss bug.
func TestWireTypesRoundTrip(t *testing.T) {
	orig := sample()
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var back model.Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(again) {
		t.Errorf("round trip changed the encoding:\n %s\n %s", raw, again)
	}
}

// A decoder must reject a payload with an unknown field rather than silently
// ignoring it. Silently ignoring is how a collector/server version skew
// becomes a missing value nobody notices.
func TestUnknownFieldIsRejectedByAStrictDecoder(t *testing.T) {
	raw := []byte(`{"schema_version":1,"tool":"certscan","surprise":"unexpected"}`)
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	var r model.Report
	if err := dec.Decode(&r); err == nil {
		t.Error("a strict decoder accepted an unknown field; ingest must be schema-closed")
	}
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
