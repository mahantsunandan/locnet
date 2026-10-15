package main

import "testing"

func TestSiteTarget(t *testing.T) {
	for in, want := range map[string]string{
		"3000":           "127.0.0.1:3000",
		":3000":          "127.0.0.1:3000",
		"localhost:8080": "localhost:8080",
		"10.0.0.5:80":    "10.0.0.5:80",
	} {
		if got, err := siteTarget(in); err != nil || got != want {
			t.Errorf("siteTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "web", "host:", "99999", "host:http"} {
		if _, err := siteTarget(bad); err == nil {
			t.Errorf("siteTarget(%q) was accepted", bad)
		}
	}
}
