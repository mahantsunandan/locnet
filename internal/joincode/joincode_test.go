package joincode

import (
	"hash/crc32"
	"strings"
	"testing"
)

func sample() Code {
	c := Code{HubAddrs: []string{"hub.example.org:8420"}}
	for i := range c.HubFingerprint {
		c.HubFingerprint[i] = byte(i)
	}
	for i := range c.Token {
		c.Token[i] = byte(200 - i)
	}
	return c
}

func TestRoundTrip(t *testing.T) {
	want := sample()
	s, err := want.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.HasPrefix(s, Prefix) {
		t.Fatalf("missing prefix: %q", s)
	}
	got, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	if !sameCode(got, want) {
		t.Fatalf("round trip mismatch\n got %+v\nwant %+v", got, want)
	}
}

// Codes get read aloud, pasted out of chat clients that capitalise the first
// letter, and broken across lines. All of that should still parse.
func TestParseTolerance(t *testing.T) {
	s, err := sample().Encode()
	if err != nil {
		t.Fatal(err)
	}
	variants := map[string]string{
		"leading/trailing space": "  " + s + "\n",
		"dashed":                 s[:20] + "-" + s[20:40] + "-" + s[40:],
		"uppercased":             strings.ToUpper(s),
		"line wrapped":           s[:30] + "\n" + s[30:],
	}
	for name, v := range variants {
		got, err := Parse(v)
		if err != nil {
			t.Errorf("%s: Parse: %v", name, err)
			continue
		}
		if !sameCode(got, sample()) {
			t.Errorf("%s: decoded to %+v", name, got)
		}
	}
}

// A truncated code is the common failure, and it must not be mistaken for a
// valid code pointing somewhere unexpected.
func TestParseRejectsCorruption(t *testing.T) {
	s, err := sample().Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"empty":         "",
		"prefix only":   Prefix,
		"wrong prefix":  "tailscale1_" + s[len(Prefix):],
		"truncated":     s[:len(s)-8],
		"flipped byte":  s[:len(Prefix)+4] + string(rotate(s[len(Prefix)+4])) + s[len(Prefix)+5:],
		"not base32":    Prefix + "!!!!!!!!!!!!",
		"trailing junk": s + "zzzzzzzz",
	}
	for name, v := range cases {
		if got, err := Parse(v); err == nil {
			t.Errorf("%s: expected an error, got %+v", name, got)
		}
	}
}

// sameCode compares two decoded codes. Code holds a slice, so == will not do.
func sameCode(a, b Code) bool {
	if a.HubFingerprint != b.HubFingerprint || a.Token != b.Token {
		return false
	}
	if len(a.HubAddrs) != len(b.HubAddrs) {
		return false
	}
	for i := range a.HubAddrs {
		if a.HubAddrs[i] != b.HubAddrs[i] {
			return false
		}
	}
	return true
}

// TestSeveralAddressesRoundTrip is the case the format exists for: a hub
// behind NAT that must be reachable from inside and outside, where no single
// address works from both.
func TestSeveralAddressesRoundTrip(t *testing.T) {
	want := sample()
	want.HubAddrs = []string{"203.0.113.27:8420", "192.168.1.64:8420", "hub.example.org:8420"}

	code, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(code)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !sameCode(got, want) {
		t.Fatalf("got %+v, want %+v", got.HubAddrs, want.HubAddrs)
	}
	// Order is the priority order and must survive exactly.
	if got.HubAddrs[0] != "203.0.113.27:8420" {
		t.Errorf("address order changed: %v", got.HubAddrs)
	}
	if got.Primary() != "203.0.113.27:8420" {
		t.Errorf("Primary() = %q", got.Primary())
	}
}

// TestVersion1CodesStillParse keeps codes issued before the upgrade working.
func TestVersion1CodesStillParse(t *testing.T) {
	// Hand-built v1 payload: magic, version 1, flags, fp, token, len, host.
	host := "192.168.1.64:8420"
	payload := []byte{'L', 'N', 1, 0}
	for i := 0; i < 16; i++ {
		payload = append(payload, byte(i))
	}
	for i := 0; i < 16; i++ {
		payload = append(payload, byte(200-i))
	}
	payload = append(payload, byte(len(host)))
	payload = append(payload, host...)

	full := binaryAppendCRC(payload)
	code := Prefix + enc.EncodeToString(full)

	got, err := Parse(code)
	if err != nil {
		t.Fatalf("a version 1 code no longer parses: %v", err)
	}
	if len(got.HubAddrs) != 1 || got.HubAddrs[0] != host {
		t.Errorf("HubAddrs = %v, want [%s]", got.HubAddrs, host)
	}
}

func TestTooManyAddressesRefused(t *testing.T) {
	c := sample()
	c.HubAddrs = nil
	for i := 0; i < 9; i++ {
		c.HubAddrs = append(c.HubAddrs, "10.0.0.1:8420")
	}
	if _, err := c.Encode(); err == nil {
		t.Fatal("nine addresses were accepted; the format caps at eight")
	}
}

func TestEncodeRejectsMissingHub(t *testing.T) {
	if _, err := (Code{}).Encode(); err == nil {
		t.Fatal("expected an error for an empty hub address")
	}
	if _, err := (Code{HubAddrs: []string{""}}).Encode(); err == nil {
		t.Fatal("expected an error for a blank hub address")
	}
}

func TestRedactHidesToken(t *testing.T) {
	s, err := sample().Encode()
	if err != nil {
		t.Fatal(err)
	}
	r := Redact(s)
	if len(r) >= len(s) {
		t.Fatalf("Redact did not shorten: %q", r)
	}
	if strings.Contains(r, s[20:40]) {
		t.Fatalf("Redact leaked the middle of the code: %q", r)
	}
}

// rotate returns a different character from the same base32 alphabet.
func rotate(c byte) byte {
	const alpha = "abcdefghijklmnopqrstuvwxyz234567"
	i := strings.IndexByte(alpha, c)
	if i < 0 {
		return 'a'
	}
	return alpha[(i+1)%len(alpha)]
}

// binaryAppendCRC closes a hand-built payload the way Encode does.
func binaryAppendCRC(payload []byte) []byte {
	sum := crc32.ChecksumIEEE(payload)
	return append(payload, byte(sum>>24), byte(sum>>16), byte(sum>>8), byte(sum))
}
