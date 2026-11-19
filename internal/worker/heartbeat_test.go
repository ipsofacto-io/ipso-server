package worker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFreshAcceptsANewFileAndRefusesAStaleOrMissingOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heartbeat")
	now := time.Now()

	if err := Fresh(path, now); err == nil || !strings.Contains(err.Error(), "heartbeat") {
		t.Fatalf("missing file: err = %v", err)
	}
	if err := writeHeartbeat(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
	if err := Fresh(path, time.Now()); err != nil {
		t.Fatalf("fresh file: %v", err)
	}

	stale := now.Add(-HeartbeatMaxAge - time.Second)
	if err := os.Chtimes(path, stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := Fresh(path, now); err == nil || !strings.Contains(err.Error(), "old") {
		t.Fatalf("stale file: err = %v", err)
	}

	ahead := now.Add(time.Minute)
	if err := os.Chtimes(path, ahead, ahead); err != nil {
		t.Fatal(err)
	}
	if err := Fresh(path, now); err == nil || !strings.Contains(err.Error(), "old") {
		t.Fatalf("future file: err = %v", err)
	}
}

func TestClearHeartbeatRemovesAFreshFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat")
	if err := writeHeartbeat(path); err != nil {
		t.Fatal(err)
	}
	if err := clearHeartbeat(path); err != nil {
		t.Fatal(err)
	}
	if err := Fresh(path, time.Now()); err == nil {
		t.Fatal("a cleared file was still fresh")
	}
	if err := clearHeartbeat(path); err != nil {
		t.Fatal(err)
	}
}

func TestFreshRejectsATimestampThatIsNotFromThisProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat")
	if err := os.WriteFile(path, []byte("not-a-time"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Fresh(path, time.Now()); err == nil {
		t.Fatal("an unreadable heartbeat was accepted")
	}
	if _, err := os.Stat("/proc/1/stat"); err != nil {
		t.Skip()
	}
	old := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Fresh(path, time.Now()); err == nil || !strings.Contains(err.Error(), "previous") {
		t.Fatalf("previous process: err = %v", err)
	}
}

func TestHeartbeatStopFinishesBeforeTheFileIsRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat")
	if err := writeHeartbeat(path); err != nil {
		t.Fatal(err)
	}
	beat := startHeartbeat(t.Context(), path, nil)
	beat.stop()
	if err := clearHeartbeat(path); err != nil {
		t.Fatal(err)
	}
	if err := Fresh(path, time.Now()); err == nil {
		t.Fatal("the file was rewritten after stop")
	}
}

func TestWriteHeartbeatDoesNotCreateTheParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "heartbeat")
	if err := writeHeartbeat(path); err == nil {
		t.Fatal("a missing parent was created")
	}
}
