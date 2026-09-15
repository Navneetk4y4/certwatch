package canary_test

import "encoding/base64"

func encodeStd(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
