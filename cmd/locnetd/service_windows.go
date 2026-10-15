package main

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/mahantsunandan/locnet/internal/paths"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// locnetService adapts the daemon to the Windows service control manager.
//
// This exists because a plain console program registered with sc.exe does not
// work: the SCM expects a status report within seconds of start and a response
// to stop requests, and kills anything that does not answer. The result looks
// like a service that randomly dies, which is a miserable thing to debug.
type locnetService struct {
	run func(context.Context) error
}

// Execute is the SCM's entry point. It reports Running, then waits for a stop
// or shutdown control while the daemon runs in the background.
func (s *locnetService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			// The daemon stopped on its own, which means something went
			// wrong. A non-zero exit code lets the SCM's restart policy
			// take over.
			changes <- svc.Status{State: svc.StopPending}
			if err != nil {
				return false, 1
			}
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done // let the tunnel come down cleanly
				return false, 0
			}
		}
	}
}

// runAsService runs under the SCM when Windows started us as a service. When
// the same binary is run from a console it reports false and the caller
// carries on in the foreground.
func runAsService(run func(context.Context) error) (bool, error) {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return false, err
	}
	if !inService {
		return false, nil
	}
	logToFile()
	return true, svc.Run("locnetd", &locnetService{run: run})
}

// logToFile points stderr at a file, because a service has no console and
// whatever it writes to stderr is discarded. Until this existed a Windows
// machine had no log at all: the share server failing to bind, the firewall
// steps, every "could not bring the tunnel up" went nowhere.
//
// The previous run's log is kept beside it once it grows past a few
// megabytes, so the file cannot fill the disk however long the service runs.
func logToFile() {
	dir := paths.LogDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	name := filepath.Join(dir, "locnetd.log")
	if fi, err := os.Stat(name); err == nil && fi.Size() > 8<<20 {
		os.Rename(name, name+".old")
	}
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	os.Stderr = f
	log.SetOutput(f)
	// The runtime writes panics to the process's stderr handle, not to
	// os.Stderr, so a crash is only recorded if the handle moves too.
	windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
}
