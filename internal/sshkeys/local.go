package sshkeys

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// hostKeyDirs are where sshd keeps its host keys.
func hostKeyDirs() []string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return []string{filepath.Join(programData, "ssh")}
	}
	return []string{"/etc/ssh"}
}

// HostKeys reads this machine's SSH host public keys.
//
// These identify the machine to anyone connecting to it. Publishing them is
// what lets a peer skip the trust-on-first-use prompt without weakening
// anything: the alternative in practice is not careful fingerprint comparison,
// it is people typing "yes" to a question they cannot answer.
func HostKeys() []string {
	var out []string
	for _, dir := range hostKeyDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, "ssh_host_") || !strings.HasSuffix(name, "_key.pub") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			if line := firstKeyField(string(b)); line != "" {
				out = append(out, line)
			}
		}
	}
	sort.Strings(out)
	return out
}

// firstKeyField trims a public key file down to "<type> <base64>", dropping the
// trailing comment.
//
// The comment is usually the generating machine's hostname, which is noise here
// and occasionally wrong — a cloned VM carries the hostname of whatever it was
// cloned from, and a known_hosts entry that disagrees with itself invites
// exactly the confusion this is meant to remove.
func firstKeyField(s string) string {
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && isKeyType(fields[0]) {
			return fields[0] + " " + fields[1]
		}
	}
	return ""
}

// isKeyType recognises the algorithm names OpenSSH writes into a .pub file.
func isKeyType(s string) bool {
	for _, prefix := range []string{"ssh-", "ecdsa-", "sk-"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// UserKey returns the operator's public key, creating one if there is none.
//
// generate is false for callers that must not have side effects — reporting to
// the hub should publish a key that exists, not conjure one on a machine whose
// owner never asked for it.
func UserKey(home string, generate bool) (string, error) {
	if home == "" {
		return "", ErrNoAccount
	}
	priv := filepath.Join(home, ".ssh", "id_ed25519")
	pub := priv + ".pub"

	if b, err := os.ReadFile(pub); err == nil {
		return firstKeyFieldWithComment(string(b)), nil
	}
	if !generate {
		return "", nil
	}

	if err := os.MkdirAll(filepath.Dir(priv), 0o700); err != nil {
		return "", err
	}
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", priv, "-N", "", "-C", "locnet")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", wrap("ssh-keygen", out, err)
	}
	b, err := os.ReadFile(pub)
	if err != nil {
		return "", err
	}
	return firstKeyFieldWithComment(string(b)), nil
}

// firstKeyFieldWithComment keeps the comment, which for an authorized_keys
// entry is useful to a human reading the file.
func firstKeyFieldWithComment(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			return t
		}
	}
	return ""
}

// Local gathers what this machine should publish.
func Local(home string, generate bool) resource.SSHKeys {
	user, _ := UserKey(home, generate)
	return resource.SSHKeys{User: user, Host: HostKeys()}
}

func wrap(what string, out []byte, err error) error {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return err
	}
	return &cmdError{what: what, msg: msg}
}

type cmdError struct{ what, msg string }

func (e *cmdError) Error() string { return e.what + ": " + e.msg }
