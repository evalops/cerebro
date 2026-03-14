package integration

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// StartJetStreamServer boots a local nats-server with JetStream enabled.
func StartJetStreamServer(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("nats-server"); err != nil {
		t.Skip("nats-server binary not found; skipping JetStream-backed integration test")
	}

	port, err := reserveFreePort()
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}

	storeDir := t.TempDir()
	// #nosec G204 -- test helper executes the fixed local nats-server binary with deterministic arguments.
	cmd := exec.CommandContext(context.Background(), "nats-server", "-js", "-a", "127.0.0.1", "-p", strconv.Itoa(port), "-sd", storeDir)

	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs

	if err := cmd.Start(); err != nil {
		t.Fatalf("start nats-server: %v", err)
	}

	natsURL := fmt.Sprintf("nats://127.0.0.1:%d", port)
	if err := waitForNATSReady(natsURL, 10*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("nats-server did not become ready: %v\nlogs:\n%s", err, logs.String())
	}

	t.Cleanup(func() {
		if cmd.Process == nil {
			return
		}
		_ = cmd.Process.Signal(os.Interrupt)

		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	return natsURL
}

func reserveFreePort() (int, error) {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = listener.Close() }()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected listener address type %T", listener.Addr())
	}
	return addr.Port, nil
}

func waitForNATSReady(natsURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		nc, err := nats.Connect(natsURL, nats.Timeout(250*time.Millisecond))
		if err == nil {
			nc.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", natsURL)
}
