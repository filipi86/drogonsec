package monitor

import (
	"errors"
	"sync"
	"testing"
)

// TestRunScanRecoversFromPanic asserts that a panic inside scanFn is contained
// inside runScan and does not propagate to the caller. The webhook endpoint
// accepts untrusted input, so a panic on a malformed event must not terminate
// the long-lived server process (availability concern).
func TestRunScanRecoversFromPanic(t *testing.T) {
	s := &webhookServer{
		scanFn: func(branch string) error {
			panic("simulated scan failure")
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// If runScan re-panics, the deferred close still runs, but the test
		// runtime will surface the panic and fail. The point of this test is
		// that no panic escapes runScan.
		s.runScan("main")
	}()
	<-done
}

// TestRunScanPropagatesNoErrorOnSuccess sanity-checks the happy path: scanFn
// returns nil and runScan completes without side-effects observable to the
// caller (errors are logged, not returned).
func TestRunScanPropagatesNoErrorOnSuccess(t *testing.T) {
	var called bool
	var mu sync.Mutex
	s := &webhookServer{
		scanFn: func(branch string) error {
			mu.Lock()
			called = true
			mu.Unlock()
			return nil
		},
	}
	s.runScan("main")
	mu.Lock()
	defer mu.Unlock()
	if !called {
		t.Fatal("scanFn was not invoked")
	}
}

// TestRunScanSwallowsError confirms that scanFn errors do not propagate as
// panics either — they are logged internally and the goroutine terminates
// cleanly.
func TestRunScanSwallowsError(t *testing.T) {
	s := &webhookServer{
		scanFn: func(branch string) error {
			return errors.New("scan failed")
		},
	}
	s.runScan("main") // must not panic
}
