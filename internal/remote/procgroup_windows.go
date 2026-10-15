package remote

import "os/exec"

// setGroup is a no-op on Windows. Job objects are the equivalent and are more
// machinery than this needs; ssh.exe on Windows does not fork a helper the way
// scp does on Unix, so killing the process is enough.
func setGroup(*exec.Cmd) {}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
}
