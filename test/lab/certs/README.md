# Committed lab fixtures

**These certificates and keys are committed on purpose.**

`certgen` is not reproducible — `ecdsa.GenerateKey` and `x509.CreateCertificate`
both call `randutil.MaybeReadByte`, so the same `-seed` gives different keys and
signatures on every run. That was measured by diffing two runs, not assumed.

Regenerating on every test run would mean a failing test could be a code change
or a fresh signature, and you could not tell which. So the fixtures are frozen
here, exactly as `test/corpus` freezes the certificate corpus.

**The private keys in this directory are lab keys for deliberately-broken
endpoints on a private Docker network. They protect nothing.** They are
committed so the lab starts without a generation step. Do not reuse them
anywhere, and do not let their presence suggest committing keys is normal —
`pkg/safeio` exists precisely to make sure real ones never get near this
codebase.

Regenerate only when a fixture must change:

```sh
go run ./test/lab/certgen -out test/lab/certs
git add test/lab/certs && git commit
```
