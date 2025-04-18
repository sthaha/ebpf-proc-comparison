package isolated

import (
	"maps"
	"slices"

	"github.com/vimalk78/ebpf-proc-hybrid/internal/ebpf"
	. "github.com/vimalk78/ebpf-proc-hybrid/internal/types"
)

type procsTracker struct {
	// currentProcs is for the previous loop-interval
	currentProcs map[Pid]ebpf.ActiveProc

	// previousProcs is for the loop-interval prior to current
	previousProcs map[Pid]ebpf.ActiveProc
}

var (
	procs = map[CPUId]procsTracker{}
	cpus  = map[Pid]CPUId{}
)

func Init(isolated []CPUId) {
	for _, cpu := range isolated {
		procs[cpu] = procsTracker{
			currentProcs:  map[Pid]ebpf.ActiveProc{},
			previousProcs: map[Pid]ebpf.ActiveProc{},
		}
	}
}

func StartTracking(cpu CPUId, proc ebpf.ActiveProc) {
	t := procs[cpu]
	t.currentProcs[proc.Pid] = proc
	cpus[proc.Pid] = cpu
}

func RemoveTracking(pid Pid) {
	cpu := cpus[pid]
	delete(cpus, pid)
	pt := procs[cpu]
	delete(pt.currentProcs, pid)
	delete(pt.previousProcs, pid)
}

func ActiveProcs() []ebpf.ActiveProc {
	activeProcs := []ebpf.ActiveProc{}
	for cpu := range maps.Keys(procs) {
		activeProcs = append(activeProcs, ActiveProcsForIsolatedCpu(cpu)...)
	}
	return activeProcs
}

func ActiveProcsForIsolatedCpu(cpu CPUId) []ebpf.ActiveProc {
	t := procs[cpu]
	if len(t.currentProcs) != 0 {
		// some activity happened on isolated cpu
		activeProcs := t.currentProcs
		// current becomes previous
		t.previousProcs = t.currentProcs
		t.currentProcs = map[Pid]ebpf.ActiveProc{}
		return slices.Collect(maps.Values(activeProcs))
	} else {
		// no activity happened on isolated cpu
		activeProcs := t.previousProcs
		// previous remains previous
		return slices.Collect(maps.Values(activeProcs))
	}
}
