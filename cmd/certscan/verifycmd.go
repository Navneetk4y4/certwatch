package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/certwatch/certwatch/pkg/safeio"
	"github.com/certwatch/certwatch/pkg/safelog"
	"github.com/certwatch/certwatch/pkg/scan"
	"github.com/certwatch/certwatch/pkg/verify"
)

// ExpectationFile is the on-disk expected-state document.
//
// A file rather than a database, deliberately: at this stage the whole product
// must run locally and send nothing anywhere, and an expectation a customer can
// read, diff and commit to their own repository is easier to trust than a row
// in someone else's database.
type ExpectationFile struct {
	Version      int                  `json:"version"`
	GeneratedAt  time.Time            `json:"generated_at,omitempty"`
	Expectations []verify.Expectation `json:"expectations"`
}

// VerifyReport is the machine-readable evidence for a verification run.
type VerifyReport struct {
	SchemaVersion int       `json:"schema_version"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"tool_version"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Label         string    `json:"environment_label,omitempty"`

	Results []verify.Result `json:"results"`
	Summary VerifySummary   `json:"summary"`
	Notes   []string        `json:"notes,omitempty"`
}

type VerifySummary struct {
	EndpointsChecked int `json:"endpoints_checked"`
	Pass             int `json:"pass"`
	Warning          int `json:"warning"`
	Drift            int `json:"drift"`
	Failure          int `json:"failure"`
	Unreachable      int `json:"unreachable"`
	Unknown          int `json:"unknown"`

	// PartialRollouts is the headline number. It is the finding no
	// hostname-level monitor produces.
	PartialRollouts       int `json:"partial_rollouts"`
	FingerprintDivergence int `json:"fingerprint_divergence"`
	Unconfirmed           int `json:"unconfirmed_expectations"`
	Alertable             int `json:"alertable"`

	TotalIPsChecked int `json:"total_ips_checked"`
}

// runVerify loads expectations, probes every resolved IP of every endpoint, and
// classifies each against its expected state.
func runVerify(ctx context.Context, opt options, log *safelog.Logger) error {
	started := time.Now().UTC()

	path, err := absPath(opt.verifyFile)
	if err != nil {
		return err
	}
	raw, err := safeio.ReadConfigFile(path)
	if err != nil {
		return fmt.Errorf("reading expectations: %w", err)
	}
	var ef ExpectationFile
	if err := json.Unmarshal(raw, &ef); err != nil {
		return fmt.Errorf("parsing expectations: %w", err)
	}
	if ef.Version != 1 {
		return fmt.Errorf("expectations file version %d is not supported (want 1)", ef.Version)
	}
	if len(ef.Expectations) == 0 {
		return fmt.Errorf("expectations file contains no expectations")
	}
	for i, e := range ef.Expectations {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("expectation %d: %w", i+1, err)
		}
	}

	rep := &VerifyReport{
		SchemaVersion: 1, Tool: "certscan", ToolVersion: Version,
		StartedAt: started, Label: opt.label,
	}
	resolver := &scan.SystemResolver{}
	policy := scan.Policy{
		RatePerSecond: 50, Concurrency: 20, DryRun: opt.dryRun, Offline: !opt.checkPublic,
	}
	cfg := verify.DefaultConfig()

	for _, e := range ef.Expectations {
		log.Info("verifying", safelog.Str("endpoint", e.Endpoint.String()),
			safelog.Str("mode", string(e.Mode)), safelog.Bool("confirmed", e.Confirmed))

		// Resolve ALL addresses. This is the step a hostname-level monitor
		// collapses, and collapsing it is exactly what hides a partial rollout.
		addrs, err := scan.ResolveAll(ctx, resolver, e.Endpoint.Hostname)
		if err != nil {
			rep.Notes = append(rep.Notes,
				fmt.Sprintf("%s: %v", e.Endpoint, err))
			rep.Results = append(rep.Results, verify.Classify(e, nil, time.Now().UTC(), cfg))
			continue
		}

		probes := make([]scan.Probe, 0, len(addrs))
		for _, a := range addrs {
			probes = append(probes, scan.ProbeOne(ctx, scan.Target{
				Addr: a, Port: e.Endpoint.Port,
				SNI: e.Endpoint.EffectiveSNI(), Hostname: e.Endpoint.Hostname,
			}, policy))
		}
		rep.Results = append(rep.Results, verify.Classify(e, probes, time.Now().UTC(), cfg))
	}

	sort.Slice(rep.Results, func(i, j int) bool {
		// Worst first: an operator reads the top of the list.
		return outcomeRank(rep.Results[i].Outcome) < outcomeRank(rep.Results[j].Outcome)
	})

	for _, r := range rep.Results {
		rep.Summary.EndpointsChecked++
		rep.Summary.TotalIPsChecked += len(r.IPsChecked)
		switch r.Outcome {
		case verify.OutcomePass:
			rep.Summary.Pass++
		case verify.OutcomeWarning:
			rep.Summary.Warning++
		case verify.OutcomeDrift:
			rep.Summary.Drift++
		case verify.OutcomeFailure:
			rep.Summary.Failure++
		case verify.OutcomeUnreachable:
			rep.Summary.Unreachable++
		case verify.OutcomeUnknown:
			rep.Summary.Unknown++
		}
		if r.PartialRollout {
			rep.Summary.PartialRollouts++
		}
		if r.FingerprintDivergence {
			rep.Summary.FingerprintDivergence++
		}
		if !r.ExpectationConfirmed {
			rep.Summary.Unconfirmed++
		}
		if r.Alertable {
			rep.Summary.Alertable++
		}
	}
	rep.FinishedAt = time.Now().UTC()

	if err := writeVerifyOutputs(rep, opt); err != nil {
		return err
	}
	printVerifySummary(rep, opt)
	return nil
}

func outcomeRank(o verify.Outcome) int {
	switch o {
	case verify.OutcomeFailure:
		return 0
	case verify.OutcomeDrift:
		return 1
	case verify.OutcomeUnreachable:
		return 2
	case verify.OutcomeWarning:
		return 3
	case verify.OutcomeUnknown:
		return 4
	}
	return 5
}

func writeVerifyOutputs(rep *VerifyReport, opt options) error {
	payload, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	if opt.out == "" && opt.htmlOut == "" {
		_, err := os.Stdout.Write(payload)
		return err
	}
	if opt.out != "" {
		f, err := os.Create(opt.out) //nolint:gosec // user-named output path
		if err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		defer f.Close()
		if _, err := f.Write(payload); err != nil {
			return err
		}
	}
	if opt.htmlOut != "" {
		html, err := renderVerifyHTML(rep)
		if err != nil {
			return err
		}
		if err := os.WriteFile(opt.htmlOut, html, 0o644); err != nil { //nolint:gosec
			return fmt.Errorf("writing HTML report: %w", err)
		}
	}
	return nil
}

func printVerifySummary(rep *VerifyReport, opt options) {
	w := os.Stderr
	s := rep.Summary
	fmt.Fprintf(w, "\n  certscan verify %s — %s\n\n", rep.ToolVersion, rep.FinishedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "  %-28s %d across %d IP addresses\n", "endpoints verified",
		s.EndpointsChecked, s.TotalIPsChecked)

	for _, row := range []struct {
		label string
		n     int
	}{
		{"FAILURE", s.Failure}, {"DRIFT", s.Drift}, {"UNREACHABLE", s.Unreachable},
		{"WARNING", s.Warning}, {"UNKNOWN", s.Unknown}, {"PASS", s.Pass},
	} {
		if row.n > 0 {
			fmt.Fprintf(w, "  %-28s %d\n", row.label, row.n)
		}
	}

	if s.PartialRollouts > 0 {
		fmt.Fprintf(w, "\n  ** %d PARTIAL ROLLOUT(S) **\n", s.PartialRollouts)
		fmt.Fprintf(w, "     Some addresses serve the expected certificate and some do not.\n")
		fmt.Fprintf(w, "     A hostname-level monitor would report these endpoints healthy.\n")
	}
	if s.FingerprintDivergence > 0 {
		fmt.Fprintf(w, "\n  %d endpoint(s) serve DIFFERENT certificates on different addresses\n",
			s.FingerprintDivergence)
	}
	if s.Unconfirmed > 0 {
		fmt.Fprintf(w, "\n  %d expectation(s) are UNCONFIRMED and cannot alert.\n", s.Unconfirmed)
	}

	// The detail. Worst first, and only what needs attention.
	for _, r := range rep.Results {
		if r.Outcome == verify.OutcomePass {
			continue
		}
		fmt.Fprintf(w, "\n  %s  %s\n", r.Outcome, r.Endpoint)
		fmt.Fprintf(w, "    expected: %s\n", r.Expected)
		fmt.Fprintf(w, "    %s\n", r.Summary)
		for _, row := range r.PerIP {
			mark := "✗"
			if row.Match {
				mark = "✓"
			}
			detail := row.Reason
			if detail == "" && row.Error != "" {
				detail = row.Error
			}
			if row.Fingerprint != "" {
				fmt.Fprintf(w, "    %s %-18s %s  %s\n", mark, row.IP, row.Fingerprint[:16], detail)
			} else {
				fmt.Fprintf(w, "    %s %-18s %-16s %s\n", mark, row.IP, "(no certificate)", detail)
			}
		}
	}

	if opt.out != "" {
		fmt.Fprintf(w, "\n  evidence written to %s\n", opt.out)
	}
	if opt.htmlOut != "" {
		fmt.Fprintf(w, "  report written to %s\n", opt.htmlOut)
	}
	fmt.Fprintf(w, "\n  This tool sent nothing anywhere.\n\n")
}
