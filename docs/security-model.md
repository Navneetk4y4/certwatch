# certscan security model

This document is for a reviewer deciding whether to let this binary run inside
your network. It states what the program can do, what it cannot, and how each
"cannot" is enforced — by the build rather than by our intentions.

## The one-paragraph version

`certscan` connects to the addresses you name, completes a TLS handshake, reads
the certificate the server presents, and closes the connection. It reads
certificate files from the directories you name. It writes a report to a file
you name. It does nothing else: no application-layer data is ever sent, no
private key is ever read, no command is ever executed, and nothing on any system
is modified.

## Invariants, and how each is enforced

| # | Invariant | Enforcement | Fails the build? |
|---|---|---|---|
| INV-1 | No private-key material leaves the process | `pkg/safeio` is the only file opener; the security canary plants a key in six shapes and greps every artefact | **Yes** |
| INV-2 | A PEM private-key block is skipped without its body being buffered | `discardPEMBlock` inspects only the END-marker prefix, using a `[]byte` view and never converting a body line to a string | **Yes** (canary) |
| INV-3 | No log line contains buffer contents | `pkg/safelog` has no `any` parameter, so a `[]byte` cannot be passed to a log call; a build check bans direct use of `log`/`log/slog` elsewhere | **Yes** |
| INV-4 | No password-protected container is ever opened | Extension denylist plus allowlist; no keystore library is a dependency | **Yes** |
| P4 | No elevated privilege is needed | No raw sockets; full TCP connect only | Reviewable |
| P5 | No command-execution path exists | A build check bans `os/exec` anywhere in the module | **Yes** |

## What an attacker gains by compromising the binary

Bounded by what the host could already reach, and by the scope you declared:

- It can connect to the addresses in your scope, which you chose.
- It can read `.pem`/`.crt`/`.cer`/`.der` files in the directories you chose.
- It holds **no credentials**, so there is nothing to steal from it.
- It cannot execute anything, write anywhere but its report, or escalate.

## Addresses that are refused unconditionally

Even if you explicitly list them in `scope.yaml`:

```
169.254.169.254   169.254.170.2   100.100.100.100   192.0.0.192   fd00:ec2::254
127.0.0.0/8       ::1/128         169.254.0.0/16    fe80::/10
224.0.0.0/4       ff00::/8        0.0.0.0/8         ::/128
metadata.google.internal, metadata.goog, instance-data
```

These are the cloud instance-metadata endpoints and the loopback/link-local
ranges. A scanner that can be pointed at `169.254.169.254` is a credential-theft
primitive, so this is the one place your configuration does not win.

**DNS rebinding** is closed structurally: a hostname is resolved **once**, every
resolved address is checked, a name resolving to *any* blocked address is
refused **entirely**, and the connection is then made **to the resolved IP
literal** with a second check inside the dialler immediately before connect. A
dialler given a hostname would re-resolve at connect time, and that
re-resolution is exactly the window a rebinding attack uses.

## Known limitations

- **Hardlinks** cross the scope boundary; `O_NOFOLLOW` does not stop them. Key
  material still cannot escape (content classification catches it) but do not
  declare a world-writable directory in scope.
- **The canary is evidence, not proof.** It tests the leak shapes it plants and
  the encodings it models (raw, standard and URL-safe base64, hex, PEM body
  lines). It cannot detect material that is compressed, encrypted, or encoded in
  a form it does not model. An earlier version planted five shapes and missed a
  sixth — a certificate with a key appended — which adversarial review found.
  That shape is now planted, and the limitation is stated here rather than
  papered over.
- **`--check-public-dns` queries 1.1.1.1 and 8.8.8.8.** This is the only
  outbound traffic besides your targets, and it is off by default.

## Reporting a vulnerability

Open a GitHub security advisory. Please do not open a public issue.
