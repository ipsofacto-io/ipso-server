package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// HeartbeatPath is where the worker writes and where ipso-server probe reads, unless
	// IPSO_PROBE_FILE names another file. The chart mounts an emptyDir there.
	HeartbeatPath = "/var/run/ipso/heartbeat"
	// HeartbeatEvery is how often a running worker replaces the file.
	HeartbeatEvery = 10 * time.Second
	// HeartbeatMaxAge is the oldest file ipso-server probe still accepts.
	HeartbeatMaxAge = 30 * time.Second
)

// Fresh reports whether the heartbeat file was written recently enough for the chart's probe.
// An empty path reads HeartbeatPath. A missing file, a clock jump, and a stale file all fail.
// On Linux the timestamp inside the file also has to be after PID 1 started. The worker is PID 1 and
// the probe is another process, so a file left on the emptyDir by the previous worker is not accepted.
func Fresh(path string, now time.Time) error {
	if path == "" {
		path = HeartbeatPath
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	age := now.Sub(info.ModTime())
	if age < 0 || age > HeartbeatMaxAge {
		return fmt.Errorf("heartbeat is %s old", age.Truncate(time.Millisecond))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	written, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	started, ok, err := processStart()
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	if ok && !written.After(started.Add(-50*time.Millisecond)) {
		return fmt.Errorf("heartbeat is from a previous process")
	}
	return nil
}

// processStart is the wall time of PID 1. The chart's worker is PID 1, and the probe is a second
// process in that container, so the probe must not compare the file with its own start time. ok is
// false where /proc is absent, which is the non-Linux test host. The chart runs on Linux.
func processStart() (time.Time, bool, error) {
	self, err := os.ReadFile("/proc/1/stat")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, err
	}
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false, err
	}
	mark := strings.LastIndex(string(self), ")")
	if mark < 0 {
		return time.Time{}, false, fmt.Errorf("unreadable /proc/1/stat")
	}
	fields := strings.Fields(string(self)[mark+1:])
	// starttime is field 22, and field 3 is the first token after the comm.
	if len(fields) < 20 {
		return time.Time{}, false, fmt.Errorf("unreadable /proc/1/stat")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return time.Time{}, false, err
	}
	var btime int64
	for line := range strings.SplitSeq(string(stat), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			btime, err = strconv.ParseInt(rest, 10, 64)
			if err != nil {
				return time.Time{}, false, err
			}
			break
		}
	}
	started, err := startedAt(btime, ticks)
	if err != nil {
		return time.Time{}, false, err
	}
	return started, true, nil
}

// startedAt converts the kernel boot time and PID 1's starttime (USER_HZ ticks) into a wall time.
// USER_HZ is 100 on the architectures this chart runs. The ticks value is converted only after it
// fits in an int64, and the seconds are added before the sub-second part so the product cannot overflow.
func startedAt(btime int64, ticks uint64) (time.Time, error) {
	const userHZ = 100
	if btime <= 0 {
		return time.Time{}, fmt.Errorf("unreadable /proc/stat")
	}
	if ticks > math.MaxInt64 {
		return time.Time{}, fmt.Errorf("unreadable /proc/1/stat")
	}
	whole := int64(ticks) / userHZ
	part := int64(ticks) % userHZ
	if whole > math.MaxInt64-btime {
		return time.Time{}, fmt.Errorf("unreadable /proc/1/stat")
	}
	return time.Unix(btime+whole, part*int64(time.Second/userHZ)).UTC(), nil
}

// clearHeartbeat removes a file left by a previous process in this pod. The emptyDir outlives a
// container restart, and a fresh file would make the probe succeed before this process passes its gates.
func clearHeartbeat(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// writeHeartbeat replaces the file. The parent directory is the chart's mount: this does not create it.
func writeHeartbeat(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(time.Now().UTC().Format(time.RFC3339Nano))
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(path, 0o600)
}

// keepHeartbeat writes the file until stop. stop waits until the loop can no longer write, so a caller
// can remove the file without the loop recreating it.
type heart struct {
	path   string
	stopCh chan struct{}
	done   chan struct{}
}

func startHeartbeat(ctx context.Context, path string, log *slog.Logger) *heart {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &heart{path: path, stopCh: make(chan struct{}), done: make(chan struct{})}
	go h.loop(ctx, log)
	return h
}

func (h *heart) loop(ctx context.Context, log *slog.Logger) {
	defer close(h.done)
	ticker := time.NewTicker(HeartbeatEvery)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := writeHeartbeat(h.path); err != nil {
				log.Error("write the heartbeat", "err", err)
			}
		}
	}
}

// stop returns only after the loop has finished, including a write that was already in progress.
func (h *heart) stop() {
	select {
	case <-h.stopCh:
	default:
		close(h.stopCh)
	}
	<-h.done
}
