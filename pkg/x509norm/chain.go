package x509norm

import (
	"encoding/pem"
	"fmt"

	"github.com/certwatch/certwatch/pkg/model"
)

// MaxChainLength bounds a presented chain. A server sending thousands of
// certificates is not a server we need to fully enumerate.
const MaxChainLength = 32

// ParsePEM extracts and normalises every CERTIFICATE block in a PEM document.
//
// Private-key blocks must never reach here: pkg/safeio strips them before any
// other code sees the bytes. As defence in depth this function refuses any
// block whose type is not CERTIFICATE, so a future caller that bypasses safeio
// still cannot feed key material into the parser.
func ParsePEM(b []byte) ([]*model.Certificate, error) {
	var out []*model.Certificate
	rest := b
	for len(rest) > 0 && len(out) < MaxChainLength {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			// Including, explicitly, any PRIVATE KEY block. Never parsed here.
			continue
		}
		c, _ := ParseDER(blk.Bytes)
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("x509norm: no CERTIFICATE block found")
	}
	return out, nil
}

// ParseChain normalises a presented chain and identifies its leaf structurally.
func ParseChain(ders [][]byte) (*model.Chain, error) {
	if len(ders) == 0 {
		return nil, fmt.Errorf("x509norm: empty chain")
	}
	if len(ders) > MaxChainLength {
		ders = ders[:MaxChainLength]
	}
	certs := make([]*model.Certificate, 0, len(ders))
	for _, d := range ders {
		c, _ := ParseDER(d)
		certs = append(certs, c)
	}
	leafIdx, outOfOrder := IdentifyLeaf(certs)

	ch := &model.Chain{
		Leaf:                certs[leafIdx],
		PresentedOutOfOrder: outOfOrder,
		Validation:          model.ChainIncomplete,
	}
	for i, c := range certs {
		if i != leafIdx {
			ch.Intermediates = append(ch.Intermediates, c)
		}
	}
	return ch, nil
}

// IdentifyLeaf finds the end-entity certificate in a set, structurally.
//
// Servers get chain order wrong often enough that trusting the presented order
// produces wrong answers in production — and "wrong certificate reported" is
// the one failure this product cannot afford.
//
// The leaf is the certificate that is not the issuer of any other certificate
// in the set. Ties are broken by preferring a non-CA certificate.
//
// Returns the index and whether the presented order was non-canonical.
func IdentifyLeaf(certs []*model.Certificate) (int, bool) {
	if len(certs) == 1 {
		return 0, false
	}

	issuesSomething := make([]bool, len(certs))
	for i, candidate := range certs {
		for j, other := range certs {
			if i == j {
				continue
			}
			if isIssuerOf(candidate, other) {
				issuesSomething[i] = true
				break
			}
		}
	}

	best, bestScore := -1, -1
	for i, c := range certs {
		if issuesSomething[i] {
			continue
		}
		// Prefer a non-CA certificate; a set of two unrelated CAs would
		// otherwise pick arbitrarily.
		score := 1
		if !c.IsCA {
			score = 2
		}
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		// Every certificate issues another: a loop, or a set of self-signed
		// certificates. Fall back to position 0 and flag it.
		return 0, true
	}
	return best, best != 0
}

// isIssuerOf reports whether a issued b.
//
// Key identifiers are preferred when both are present: DN string equality is
// fragile across encodings, and two different CAs can legitimately share a DN
// string after normalisation.
func isIssuerOf(a, b *model.Certificate) bool {
	if a == nil || b == nil {
		return false
	}
	if a.SubjectKeyID != "" && b.IssuerKeyID != "" {
		return a.SubjectKeyID == b.IssuerKeyID
	}
	if a.SubjectDN == "" || b.IssuerDN == "" {
		return false
	}
	return a.SubjectDN == b.IssuerDN && a.Fingerprint != b.Fingerprint
}
