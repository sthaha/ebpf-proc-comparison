package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "log/slog"

	"github.com/alecthomas/kingpin"
	"github.com/prometheus/procfs"
)

var (
	app              = kingpin.New("activeproc", "reads only active processes from /proc to get process cpu usage")
	loopInterval     = app.Flag("loop-interval", "loop interval").Default("1000ms").Duration()
	enablePprof      = app.Flag("enable-pprof", "enable profiling with pprof").Default("false").Bool()
	fullScanInterval = app.Flag("full-scan-interval", "iterations between full process scans").Default("3").Int()
)

type ProcInfo struct {
	Pid           uint32
	Comm          string
	LastUtime     uint
	LastStime     uint
	LastCheckTime time.Time
	IsActive      bool
}

type ProcTracker struct {
	procs    map[uint32]*ProcInfo
	interval time.Duration
}

func NewTracker(interval time.Duration) *ProcTracker {
	return &ProcTracker{
		procs:    make(map[uint32]*ProcInfo),
		interval: interval,
	}
}

func (pt *ProcTracker) ActivePids() []uint32 {
	result := make([]uint32, 0, len(pt.procs))
	for pid, info := range pt.procs {
		if !info.IsActive {
			continue
		}
		result = append(result, pid)
	}
	return result
}

func (pt *ProcTracker) UpdateProc(pid uint32, utime, stime uint, comm string, now time.Time) bool {
	// Skip kernel workers and swapper processes like in the eBPF implementation
	if strings.HasPrefix(comm, "swapper/") || strings.HasPrefix(comm, "kworker") {
		return false
	}

	info, exists := pt.procs[pid]
	if !exists {
		// New process
		pt.procs[pid] = &ProcInfo{
			Pid:           pid,
			Comm:          comm,
			LastUtime:     utime,
			LastStime:     stime,
			LastCheckTime: now,
			IsActive:      true,
		}
		return true
	}

	info.Comm = comm

	if utime > info.LastUtime || stime > info.LastStime {
		info.LastUtime = utime
		info.LastStime = stime
		info.LastCheckTime = now
		info.IsActive = true
		return true
	}

	// NOTE: no CPU time change for some time, consider it inactive
	if now.Sub(info.LastCheckTime) > 3*pt.interval {
		info.IsActive = false
	}

	return info.IsActive
}

func (pt *ProcTracker) RemoveProc(pid uint32) {
	delete(pt.procs, pid)
}

func (pt *ProcTracker) FullScan() (int, error) {
	allProcs, err := procfs.AllProcs()
	if err != nil {
		return 0, err
	}

	log.Info("Scanning for active processes", "num", len(allProcs))

	now := time.Now()

	// Mark processes as seen in this scan
	seen := make(map[uint32]bool, len(allProcs))
	activeCount := 0

	for _, proc := range allProcs {
		pid := uint32(proc.PID)
		seen[pid] = true

		// Read process stats
		stat, err := proc.Stat()
		if err != nil {
			continue
		}

		if !pt.UpdateProc(pid, stat.UTime, stat.STime, stat.Comm, now) {
			continue
		}
		activeCount++
	}

	// filter out inactive ones
	for pid := range pt.procs {
		if !seen[pid] {
			delete(pt.procs, pid)
		}
	}

	return activeCount, nil
}

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	if *enablePprof {
		go func() {
			http.ListenAndServe(":6060", http.DefaultServeMux)
		}()
	}

	tracker := NewTracker(*loopInterval)
	activeCount, err := tracker.FullScan()
	if err != nil {
		log.Error("initial scan failed", "error", err)
	} else {
		log.Info("Initial scan complete", "activeProcs", activeCount)
	}

	ticker := time.NewTicker(*loopInterval)
	defer ticker.Stop()

	oldTs := time.Now()
	scanCounter := 0
	running := true

	// Single-threaded event loop
	for running {
		select {
		case <-sigs:
			log.Info("received signal, shutting down...")
			running = false

		case newTs := <-ticker.C:
			timeDiffSec := newTs.Sub(oldTs).Seconds()
			if timeDiffSec < 0.1 {
				continue
			}

			// Process active PIDs
			startTime := time.Now()
			activeCount := processActivePids(tracker)

			scanCounter++
			if scanCounter >= *fullScanInterval {
				scanCounter = 0
				newActive, err := tracker.FullScan()
				if err != nil {
					log.Error("full scan failed", "error", err)
				} else {
					log.Info("Full scan complete", "newActiveProcs", newActive)
				}
			}

			log.Info("ActiveProcs", "num", activeCount, "cost", time.Since(startTime).String())
			oldTs = newTs
		}
	}

	log.Info("Exiting...")
}

func processActivePids(tracker *ProcTracker) int {
	activePids := tracker.ActivePids()
	activeCount := 0
	now := time.Now()

	for _, pid := range activePids {
		proc, err := procfs.NewProc(int(pid))
		if err != nil {
			// Process probably exited
			tracker.RemoveProc(pid)
			continue
		}

		stat, err := proc.Stat()
		if err != nil {
			continue
		}

		// Update process activity status
		if tracker.UpdateProc(pid, stat.UTime, stat.STime, stat.Comm, now) {
			activeCount++
		}
	}

	return activeCount
}
