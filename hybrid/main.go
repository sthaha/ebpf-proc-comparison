package main

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	log "log/slog"

	"github.com/alecthomas/kingpin"
	"github.com/vimalk78/ebpf-proc-hybrid/internal/ebpf"
	"github.com/vimalk78/ebpf-proc-hybrid/internal/isolated"
	"github.com/vimalk78/ebpf-proc-hybrid/internal/proc"
)

var (
	bpfInstance = ebpf.MustInstance()

	isolatedCPUs = proc.MustGetIsolatedCPUs()

	app          = kingpin.New("ebpf-proc-hybrid", "an ebpf + /proc hybrid approach to get procsess cpu usage")
	loopInterval = app.Flag("loop-interval", "loop interval").Default("1000ms").Duration()
	enablePprof  = app.Flag("enable-pprof", "enable profiling with pprof").Default("false").Bool()
	onlyIsolated = app.Flag("only-isolated", "check only isolated cpus").Default("false").Bool()
)

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))
	// Subscribe to signals for terminating the program
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		cancel()
	}()
	if *enablePprof {
		setupPprof()
	}

	doneCh := make(chan struct{})
	go run(ctx, doneCh)

	<-ctx.Done()
	log.Info("received Ctrl-C.")
	<-doneCh
	log.Info("Shutting down...")
	bpfInstance.Close()
}

func run(ctx context.Context, doneCh chan struct{}) {
	log.Info("Starting loop", "interval", loopInterval)
	log.Info("Isolated CPUs", "num", len(isolatedCPUs), "cpus", isolatedCPUs)
	isolated.Init(isolatedCPUs)
	ticker := time.Tick(*loopInterval)
	oldTs := time.Now()

	for {
		select {
		case newTs := <-ticker:
			timeDiffSec := newTs.Sub(oldTs).Seconds()
			if timeDiffSec < 0.1 {
				continue
			}
			procsRead := 0
			// get active procs from ebpf
			activeProcs, err := bpfInstance.GetActiveProcs()
			if err != nil {
				log.Error("Error reading active procs", "error", err)
			}
			// read /proc/<pid>/stat for each active proc
			for _, activeProc := range activeProcs {
				if slices.Contains(isolatedCPUs, activeProc.Cpu) {
					isolated.StartTracking(activeProc.Cpu, activeProc)
				} else {
					if !*onlyIsolated {
						// deliberately ignoring the returned values
						_, _, _, err := proc.ReadPidProcStat(activeProc.Pid)
						if err != nil {
							log.Error("cannot read /proc/<pid>/stat", "proc", activeProc)
						} else {
							procsRead += 1
						}
					}
				}
			}
			// get active procs from isolated cpus
			isolatedActiveProcs := isolated.ActiveProcs()
			for _, isolatedActiveProc := range isolatedActiveProcs {
				// deliberately ignoring the returned values
				_, _, _, err := proc.ReadPidProcStat(isolatedActiveProc.Pid)
				if err != nil {
					log.Error("cannot read /proc/<pid>/stat", "proc", isolatedActiveProc)
					isolated.RemoveTracking(isolatedActiveProc.Pid)
				} else {
					procsRead += 1
				}
			}
			log.Info("ActiveProcs", "num", procsRead, "cost", time.Since(newTs).String())

		case <-ctx.Done():
			log.Info("loop finished...")
			close(doneCh)
			return
		}
	}
}

func setupPprof() {
	go func() {
		http.ListenAndServe(":6060", http.DefaultServeMux)
	}()
}
