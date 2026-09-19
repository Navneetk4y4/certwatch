package main

import (
	"bytes"
	"html/template"
	"time"

	"github.com/certwatch/certwatch/pkg/verify"
)

// renderVerifyHTML produces a self-contained report.
//
// SELF-CONTAINED IS THE POINT: no CDN, no external font, no analytics, no
// script that phones anywhere. It is a file a customer can open on an air-gapped
// laptop, and it must be as verifiable as the claim that the scanner sends
// nothing anywhere. A report that loads a remote asset would quietly falsify
// the product's central promise.
func renderVerifyHTML(rep *VerifyReport) ([]byte, error) {
	t, err := template.New("report").Funcs(template.FuncMap{
		"short": func(s string) string {
			if len(s) > 16 {
				return s[:16]
			}
			return s
		},
		"outcomeClass": func(o verify.Outcome) string {
			switch o {
			case verify.OutcomeFailure:
				return "fail"
			case verify.OutcomeDrift:
				return "drift"
			case verify.OutcomeWarning:
				return "warn"
			case verify.OutcomeUnreachable, verify.OutcomeUnknown:
				return "unk"
			}
			return "pass"
		},
		"ts": func(t time.Time) string { return t.Format("2006-01-02 15:04:05 MST") },
	}).Parse(reportTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, rep); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const reportTemplate = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>certscan — TLS verification report</title>
<style>
:root{
  --bg:#fbfaf8; --fg:#1a1a1a; --muted:#6b6660; --line:#e3ded6; --card:#fff;
  --pass:#1a7f4b; --passbg:#eaf6ef; --fail:#b3261e; --failbg:#fdecea;
  --drift:#8a5a00; --driftbg:#fdf3e0; --warn:#8a5a00; --warnbg:#fdf3e0;
  --unk:#5a5a5a; --unkbg:#f0efed; --accent:#2a4d8f;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#17161a; --fg:#eceaf0; --muted:#a09aa8; --line:#2f2d35; --card:#1e1d23;
  --passbg:#13291d; --failbg:#2e1513; --driftbg:#2b2110; --warnbg:#2b2110; --unkbg:#232227;
  --pass:#5fd39a; --fail:#f08b84; --drift:#e8b45e; --warn:#e8b45e; --unk:#a5a1ab; --accent:#8fb0ec;
}}
:root[data-theme=dark]{
  --bg:#17161a; --fg:#eceaf0; --muted:#a09aa8; --line:#2f2d35; --card:#1e1d23;
  --passbg:#13291d; --failbg:#2e1513; --driftbg:#2b2110; --warnbg:#2b2110; --unkbg:#232227;
  --pass:#5fd39a; --fail:#f08b84; --drift:#e8b45e; --warn:#e8b45e; --unk:#a5a1ab; --accent:#8fb0ec;
}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);margin:0;padding-block:2.5rem;
  font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:0 20px}
h1{font-size:1.45rem;margin:0 0 .2rem;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:.87rem;margin-bottom:2rem}
.counts{display:flex;flex-wrap:wrap;gap:.6rem;margin-bottom:2rem}
.count{background:var(--card);border:1px solid var(--line);border-radius:10px;
  padding:.7rem 1rem;min-width:104px}
.count b{display:block;font-size:1.5rem;line-height:1.15;font-variant-numeric:tabular-nums}
.count span{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.count.fail b{color:var(--fail)} .count.pass b{color:var(--pass)}
.count.drift b{color:var(--drift)} .count.warn b{color:var(--warn)}
.banner{background:var(--failbg);border:1px solid var(--fail);border-left-width:4px;
  border-radius:8px;padding:1rem 1.1rem;margin-bottom:2rem}
.banner h2{margin:0 0 .35rem;font-size:1rem;color:var(--fail)}
.banner p{margin:0;font-size:.88rem;color:var(--fg)}
.ep{background:var(--card);border:1px solid var(--line);border-radius:12px;
  margin-bottom:1.1rem;overflow:hidden}
.ep-head{padding:.95rem 1.15rem;border-bottom:1px solid var(--line);
  display:flex;flex-wrap:wrap;gap:.7rem;align-items:center}
.ep-name{font-weight:600;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.95rem}
.pill{font-size:.7rem;font-weight:700;letter-spacing:.06em;padding:.2rem .55rem;
  border-radius:999px;text-transform:uppercase}
.pill.pass{background:var(--passbg);color:var(--pass)}
.pill.fail{background:var(--failbg);color:var(--fail)}
.pill.drift{background:var(--driftbg);color:var(--drift)}
.pill.warn{background:var(--warnbg);color:var(--warn)}
.pill.unk{background:var(--unkbg);color:var(--unk)}
.tag{font-size:.7rem;color:var(--muted);border:1px solid var(--line);
  padding:.15rem .5rem;border-radius:999px}
.flow{display:flex;flex-wrap:wrap;align-items:stretch;gap:0;padding:1.05rem 1.15rem .4rem}
.step{flex:1 1 150px;min-width:0;padding-right:1.1rem;position:relative}
.step:not(:last-child)::after{content:"→";position:absolute;right:.32rem;top:1.45rem;
  color:var(--line);font-size:1.05rem}
.step h4{margin:0 0 .35rem;font-size:.67rem;text-transform:uppercase;
  letter-spacing:.07em;color:var(--muted);font-weight:700}
.step .v{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem;
  word-break:break-word}
.summary{padding:.2rem 1.15rem 1rem;font-size:.88rem;color:var(--fg)}
table{width:100%;border-collapse:collapse;font-size:.83rem}
.tw{overflow-x:auto;border-top:1px solid var(--line)}
th{text-align:left;padding:.6rem 1.15rem;font-size:.68rem;text-transform:uppercase;
  letter-spacing:.06em;color:var(--muted);border-bottom:1px solid var(--line);font-weight:700}
td{padding:.6rem 1.15rem;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
td.ip,td.fp{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;white-space:nowrap}
.m{font-weight:700} .m.y{color:var(--pass)} .m.n{color:var(--fail)}
.why{color:var(--muted);font-size:.8rem}
tr.bad{background:var(--failbg)}
.foot{margin-top:2.5rem;padding-top:1.2rem;border-top:1px solid var(--line);
  color:var(--muted);font-size:.8rem}
.foot code{background:var(--unkbg);padding:.1rem .35rem;border-radius:4px;font-size:.76rem}
@media(max-width:620px){.flow{display:block}.step{padding:0 0 .9rem}.step::after{display:none}}
</style></head><body><div class="wrap">

<h1>TLS verification report</h1>
<div class="sub">certscan {{.ToolVersion}} · {{ts .FinishedAt}}{{if .Label}} · {{.Label}}{{end}} ·
{{.Summary.EndpointsChecked}} endpoint(s) across {{.Summary.TotalIPsChecked}} IP address(es)</div>

{{if gt .Summary.PartialRollouts 0}}
<div class="banner">
  <h2>{{.Summary.PartialRollouts}} partial rollout{{if gt .Summary.PartialRollouts 1}}s{{end}} detected</h2>
  <p>Some addresses behind these hostnames serve the expected certificate and some do not.
     A monitor that checks the hostname connects once, gets whichever address answers,
     and reports these endpoints healthy.</p>
</div>
{{end}}

<div class="counts">
  <div class="count fail"><b>{{.Summary.Failure}}</b><span>failure</span></div>
  <div class="count drift"><b>{{.Summary.Drift}}</b><span>drift</span></div>
  <div class="count warn"><b>{{.Summary.Warning}}</b><span>warning</span></div>
  <div class="count"><b>{{.Summary.Unreachable}}</b><span>unreachable</span></div>
  <div class="count"><b>{{.Summary.Unknown}}</b><span>unknown</span></div>
  <div class="count pass"><b>{{.Summary.Pass}}</b><span>pass</span></div>
</div>

{{range .Results}}
<div class="ep">
  <div class="ep-head">
    <span class="ep-name">{{.Endpoint.Hostname}}:{{.Endpoint.Port}}</span>
    <span class="pill {{outcomeClass .Outcome}}">{{.Outcome}}{{if .SubReason}} · {{.SubReason}}{{end}}</span>
    <span class="tag">{{.ExpectationMode}}</span>
    {{if not .ExpectationConfirmed}}<span class="tag">unconfirmed — cannot alert</span>{{end}}
    {{if .FingerprintDivergence}}<span class="tag">certificates differ across IPs</span>{{end}}
  </div>

  <div class="flow">
    <div class="step"><h4>Expected</h4><div class="v">{{.Expected}}</div></div>
    <div class="step"><h4>Resolved IPs</h4><div class="v">{{len .IPsResolved}} address(es)<br>
      {{range .IPsResolved}}{{.}}<br>{{end}}</div></div>
    <div class="step"><h4>Actual</h4><div class="v">
      {{range .PerIP}}{{if .Fingerprint}}{{short .Fingerprint}}<br>{{end}}{{end}}
      {{if not .IPsChecked}}—{{end}}</div></div>
    <div class="step"><h4>Match</h4><div class="v">{{len .IPsMatching}} of {{len .IPsChecked}} checked</div></div>
    <div class="step"><h4>Result</h4><div class="v">
      {{if .PartialRollout}}{{if .Suppressed}}<strong style="color:var(--warn)">PARTIAL ROLLOUT (in grace window)</strong>{{else}}<strong style="color:var(--fail)">PARTIAL ROLLOUT</strong>{{end}}
      {{else}}{{.Outcome}}{{end}}</div></div>
  </div>

  <div class="summary">{{.Summary}}</div>

  {{if .PerIP}}
  <div class="tw"><table>
    <thead><tr><th>IP address</th><th>Certificate (SHA-256)</th><th>Subject</th>
      <th>Expires</th><th>Days</th><th>Match</th><th>Detail</th></tr></thead>
    <tbody>
    {{range .PerIP}}
    <tr{{if and .Handshake (not .Match)}} class="bad"{{end}}>
      <td class="ip">{{.IP}}:{{.Port}}</td>
      <td class="fp">{{if .Fingerprint}}{{short .Fingerprint}}…{{else}}—{{end}}</td>
      <td>{{if .SubjectCN}}{{.SubjectCN}}{{else}}—{{end}}</td>
      <td>{{if .NotAfter}}{{.NotAfter}}{{else}}—{{end}}</td>
      <td>{{if .DaysRemaining}}{{.DaysRemaining}}{{else}}—{{end}}</td>
      <td class="m {{if .Match}}y{{else}}n{{end}}">{{if .Match}}MATCH{{else if .Handshake}}DRIFT{{else}}—{{end}}</td>
      <td class="why">{{if .Reason}}{{.Reason}}{{else}}{{.Error}}{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table></div>
  {{end}}
</div>
{{end}}

{{if .Notes}}
<div class="ep"><div class="ep-head"><span class="ep-name">Coverage notes</span></div>
<div class="summary">{{range .Notes}}{{.}}<br>{{end}}</div></div>
{{end}}

<div class="foot">
  <p><strong>This report is self-contained.</strong> No external stylesheet, font, script or image.
     It made no network request to produce this page, and it makes none to display it.</p>
  <p>Every address a hostname resolved to was connected to separately and its certificate read
     from a real TLS handshake. Session resumption is disabled, so a cached certificate cannot
     mask a change. Verified against the expected state in the expectations file.</p>
  <p>Generated by <code>certscan verify</code> {{.ToolVersion}}. Machine-readable evidence is in
     the JSON report.</p>
</div>
</div></body></html>`
