package remote

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

// decodePS reverses powershellCommand, so a test can read the script that
// would run on the far machine.
func decodePS(t *testing.T, cmdline string) string {
	t.Helper()
	const prefix = "powershell -NoProfile -NonInteractive -EncodedCommand "
	if !strings.HasPrefix(cmdline, prefix) {
		t.Fatalf("not an encoded PowerShell command: %q", cmdline)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(cmdline, prefix))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw)%2 != 0 {
		t.Fatalf("odd length %d: not UTF-16", len(raw))
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

func TestPowershellCommandRoundTrips(t *testing.T) {
	// Quotes, a dollar sign and a non-ASCII rune: everything cmd.exe or a
	// PowerShell command line would otherwise mangle.
	script := `Write-Output "it's $HOME — ok" | Out-Null`
	if got := decodePS(t, powershellCommand(script)); !strings.HasSuffix(got, "\n"+script) {
		t.Fatalf("round trip gave %q", got)
	}
}

func TestWindowsJobScript(t *testing.T) {
	got := decodePS(t, windowsJobScript(".locnet/jobs/sim-1", "python run.py", []string{"SEED=it's 7"}))
	for _, want := range []string{
		`Set-Location -LiteralPath (Join-Path $HOME '.locnet/jobs/sim-1') -ErrorAction Stop`,
		`${env:SEED} = 'it''s 7'`,
		"python run.py\n",
		"exit $LASTEXITCODE",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("script lacks %q:\n%s", want, got)
		}
	}
}

func TestWindowsTargetsSkipRsyncAndShellQuotes(t *testing.T) {
	win := Target{OS: "windows"}
	if useRsync(win) {
		t.Error("rsync chosen for a Windows peer")
	}
	if got := remotePath(win, "My Docs/a.txt"); got != "My Docs/a.txt" {
		t.Errorf("Windows remote path = %q, want it unquoted", got)
	}
	if got := remotePath(Target{OS: "linux"}, "a b"); got != "'a b'" {
		t.Errorf("Unix remote path = %q, want it shell-quoted", got)
	}
}
