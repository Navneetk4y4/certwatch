# certscan

Find every TLS certificate across your estate — including the internal ones a
public scanner cannot reach — and see which of them you are not tracking.

## **This tool sends nothing anywhere**

No telemetry. No phone-home. No update check. No account. No licence key.

It writes a report to your disk and exits. In the default mode the **only**
outbound connections it makes are TLS handshakes to the targets you named on the
command line. Nothing else leaves your machine.

You do not have to take that on faith. There is exactly one package in this
repository that opens a network connection (`pkg/scan`) and exactly one that
opens a file (`pkg/safeio`). A build check fails the build if any other package
does either. See **Verifying the claims** below.

## **It never reads a private key**

All file access goes through `pkg/safeio`, which:

- opens **only** `.pem`, `.crt`, `.cer` and `.der` files — a `.key` or a `.p12`
  is rejected before a single byte of it is read;
- **never follows a symlink** (`O_NOFOLLOW` at open, not merely a check
  beforehand);
- skips any PEM block labelled as a private key **without buffering its
  contents**;
- skips any binary blob it cannot positively confirm is a certificate — 
  ambiguity always resolves toward *not reading*;
- **counts and reports every skip**, so you can see what was not looked at.

A test called the *security canary* plants a synthetic private key in six
different shapes, runs a full scan, and searches every byte the program
produces — output, logs at debug verbosity, and on-disk state — for any trace of
it. It fails the build on a single hit. It also asserts the scanner still found
the real certificates, because a scanner that reads nothing would pass a leak
test trivially.

---

## Install

Download a signed binary from the releases page, or build it yourself:

```sh
git clone https://github.com/certwatch/certwatch
cd certwatch
make build          # produces build/certscan
```

The build is reproducible: two independent builds of the same commit produce
byte-identical binaries, so you can verify a published binary matches this
source. `make repro` checks that.

## Use

**Always dry-run a range you have not scanned before.** It prints the target
list and sends zero packets.

```sh
certscan --cidr 10.20.0.0/22 --dry-run
```

Then scan it:

```sh
certscan --cidr 10.20.0.0/22 --out report.json
```

Check named hosts, and read a local certificate directory:

```sh
certscan --hosts api.example.com,vpn.example.com --dirs /etc/ssl/certs
```

Use a scope file instead of flags:

```yaml
# scope.yaml
version: 1
cidrs:
  - 10.20.0.0/16
ports: [443, 8443]
certificate_directories:
  - /etc/ssl/certs
rate_limit_per_second: 50
```

```sh
certscan --scope scope.yaml --out report.json
```

Run `certscan --help` for every flag.

## What you get

A human summary on stderr and a machine-readable report on disk:

```
  unique certificates found          412
  endpoints responding               289

  reachability from the internet
  not publicly resolvable            123
  publicly resolvable                289

  expiry
  already expired                      4
  expiring within 30 days             11
  expiring within 60 days             27

  ** 2 hostname(s) served DIFFERENT certificates on different IPs **
     This usually means a deploy updated some load-balancer members and not others.

  files not read
       3  contained private-key material, which is never read or transmitted
       1  file type not opened (only .pem .crt .cer .der are read)
```

The report schema is stable and documented in `pkg/model/report.go`. It includes
a **coverage** section that states plainly what was *not* covered — a partial
scan presented as complete is worse than no scan, because you would believe it.

## Permissions it needs, and why

| Needs | Why | Notes |
|---|---|---|
| Outbound TCP to the ports you name | To complete a TLS handshake and read the certificate | It sends **no application-layer data**. It connects, completes the handshake, and closes |
| Read access to the directories you name | To find certificates already on disk | Only `.pem`, `.crt`, `.cer`, `.der`. Never a key or a keystore |
| Outbound DNS | To resolve the hostnames you name | Your system resolver |
| Outbound DNS to 1.1.1.1 and 8.8.8.8 | **Only with `--check-public-dns`** | To tell which findings are reachable from the internet. Off by default |

It does **not** need root. It does **not** need any capability
(`CapabilityBoundingSet=` can be empty). It uses no raw sockets, so it cannot
sniff traffic even if you wanted it to.

## What it deliberately does not do

- It does **not** probe for vulnerabilities, grab banners, or fingerprint
  software versions.
- It does **not** test cipher suites for weakness. `testssl.sh` exists and is
  excellent.
- It does **not** enumerate subdomains or brute-force hostnames.
- It does **not** read private keys, keystores (PKCS#12, JKS, JCEKS, PFX, BKS),
  or anything outside the directories you name.
- It does **not** change anything. There is no write path to any system but its
  own report file.

## Verifying the claims

Every claim above is checked by the build. You can run the same checks:

```sh
make check      # everything CI runs
make canary     # the private-key leak test, on its own
```

| Claim | How to verify it yourself |
|---|---|
| "sends nothing anywhere" | `grep -rn "net\.\|http\." pkg/ cmd/ --include=*.go` — network code exists only in `pkg/scan` |
| "only safeio opens a file" | `go run ./internal/tools/importcheck -root .` — fails the build otherwise |
| "no private key ever leaves" | `make canary` — plants a key in six shapes and greps every artefact |
| "no command execution" | The same check bans `os/exec` anywhere in the module |
| "reproducible build" | `make repro` — two builds, compared byte for byte |
| The scan is bounded | `pkg/scan/ratelimit.go` — 60 lines, no dependency |

## Known limitations

Stated because a tool that hides its gaps is not trustworthy:

- **Hardlinks cross the scope boundary.** `O_NOFOLLOW` stops symlinks but not
  hardlinks, so a hardlink inside a scanned directory pointing outside it will
  be read. Key material still cannot escape — the content classifiers refuse it
  whatever path it arrived by — but do not declare a world-writable directory in
  your scope.
- **A corrupt DER file is skipped, not reported as a broken certificate.** For
  binary files the classifier fails closed, because a blob it cannot confirm is
  a certificate could be anything, including a key. Corrupt **PEM** certificates
  *are* reported, with `parse_status: unparseable`, because the block label is
  explicit. Both cases are counted.
- **IPv6 ranges wider than /112 are refused**, not truncated. A /64 is not
  enumerable and pretending otherwise produces a scan that never finishes.
- **`publicly_resolvable` is `null` unless you pass `--check-public-dns`.** It
  is not guessed. A report claiming "0% publicly resolvable" because it could
  not check would be a lie.

## Licence and status

Pre-release. The report schema is versioned (`schema_version`) and will stay
backward-compatible within a major version.
