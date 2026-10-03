// Package keyscan recognises private-key material in bytes.
//
// INV-5. Used on both sides of the wire: the collector refuses to spool or
// send anything that matches, and the server refuses to accept it. Two copies
// of one check, deliberately — the second exists because the first can have
// a bug.
package keyscan

import "regexp"

// keyPatterns are the shapes private-key material takes in a payload.
//
// INV-5. Deliberately broad: a false positive costs a collector one rejected
// batch and a loud error; a false negative means key material in our database.
// The asymmetry is the entire argument for erring wide.
var keyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)-----BEGIN[ A-Z]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)-----BEGIN[ A-Z]*ENCRYPTED PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bPuTTY-User-Key-File\b`),
	regexp.MustCompile(`(?i)\bprivateKeyPem\b|\bprivate_key_pem\b|\bprivateKey\b`),
	// PKCS#8 and PKCS#1 DER headers, base64-encoded. These are what a buggy
	// collector that base64s a whole file would actually send.
	regexp.MustCompile(`MII[A-Za-z0-9+/]{6,}(?:BAD|AgEAAo|EvAIBA|EvQIBA)`),
	regexp.MustCompile(`(?i)\bBEGIN RSA PRIVATE\b|\bBEGIN EC PRIVATE\b|\bBEGIN DSA PRIVATE\b`),
}

// Scan returns the pattern that matched, or empty. The pattern, never the
// match: a caller that logged the match would log the key.
func Scan(raw []byte) string {
	for _, re := range keyPatterns {
		if re.Match(raw) {
			return re.String()
		}
	}
	return ""
}
