package node

import (
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

// countingTUN stands in for a real tunnel device in filter tests. Only Write
// is exercised; the rest satisfies the interface.
type countingTUN struct {
	written int
}

func (c *countingTUN) File() *os.File { return nil }

func (c *countingTUN) Read([][]byte, []int, int) (int, error) { return 0, nil }

func (c *countingTUN) Write(bufs [][]byte, _ int) (int, error) {
	c.written += len(bufs)
	return len(bufs), nil
}

func (c *countingTUN) MTU() (int, error)        { return 1280, nil }
func (c *countingTUN) Name() (string, error)    { return "test0", nil }
func (c *countingTUN) Events() <-chan tun.Event { return nil }
func (c *countingTUN) Close() error             { return nil }
func (c *countingTUN) BatchSize() int           { return 1 }
