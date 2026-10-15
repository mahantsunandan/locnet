package hubapi

import (
	"encoding/json"
	"testing"
)

func TestWithNonceKeepsTheBodyAndMakesItUnique(t *testing.T) {
	for _, in := range []string{`{}`, `{"id":"j1","brief":true}`, `{ "a": 1 }`} {
		a, b := WithNonce([]byte(in)), WithNonce([]byte(in))
		if string(a) == string(b) {
			t.Errorf("%s: two calls gave the same body", in)
		}
		var got, want map[string]any
		if err := json.Unmarshal(a, &got); err != nil {
			t.Fatalf("%s became invalid JSON %s: %v", in, a, err)
		}
		_ = json.Unmarshal([]byte(in), &want)
		if got["nonce"] == nil {
			t.Errorf("%s: no nonce in %s", in, a)
		}
		delete(got, "nonce")
		if len(got) != len(want) {
			t.Errorf("%s became %s", in, a)
		}
	}
	for _, in := range []string{`null`, `[1,2]`, ``} {
		if got := string(WithNonce([]byte(in))); got != in {
			t.Errorf("%q changed to %q", in, got)
		}
	}
}
