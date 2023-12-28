//go:build bpf && !386
// +build bpf,!386

/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package bpf

import (
	_ "embed"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gravitational/trace"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/observability/metrics"
)

var (
	lostCommandEvents = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: teleport.MetricLostCommandEvents,
			Help: "Number of lost command events.",
		},
	)
)

const (
	commandEventsBuffer = "execve_events"
)

// rawExecEvent is sent by the eBPF program that Teleport pulls off the perf
// buffer.
type rawExecEvent struct {
	// PID is the ID of the process.
	PID uint64

	// PPID is the PID of the parent process.
	PPID uint64

	// Command is the executable.
	Command [CommMax]byte

	// Type is the type of event.
	Type int32

	// Argv is the list of arguments to the program.
	Argv [ArgvMax]byte

	// ReturnCode is the return code of execve.
	ReturnCode int32

	// CgroupID is the internal cgroupv2 ID of the event.
	CgroupID uint64
}

type exec struct {
	//session
	objs commandObjects

	eventBuf *ringbuf.Reader
	lost     *ebpf.Map
	toClose  []interface{ Close() error }

	bpfEvents chan []byte
}

func (e *exec) startSession(cgroupID uint64) error {
	if err := e.objs.MonitoredCgroups.Put(cgroupID, int64(0)); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (e *exec) endSession(cgroupID uint64) error {
	if err := e.objs.MonitoredCgroups.Delete(&cgroupID); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// startExec will load, start, and pull events off the ring buffer
// for the BPF program.
func startExec(bufferSize int) (*exec, error) {
	err := metrics.RegisterPrometheusCollectors(lostCommandEvents)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, trace.WrapWithMessage(err, "Removing memlock")
	}

	var objs commandObjects
	if err := loadCommandObjects(&objs, nil); err != nil {
		return nil, trace.Wrap(err)
	}

	toClose := make([]interface{ Close() error }, 0)

	tracePoints := []struct {
		group      string
		name       string
		tracepoint *ebpf.Program
	}{
		{
			group:      "syscalls",
			name:       "sys_enter_execve",
			tracepoint: objs.TracepointSyscallsSysEnterExecve,
		},
		{
			group:      "syscalls",
			name:       "sys_exit_execve",
			tracepoint: objs.TracepointSyscallsSysExitExecve,
		},
		{
			group:      "syscalls",
			name:       "sys_enter_execveat",
			tracepoint: objs.TracepointSyscallsSysEnterExecveat,
		},
		{
			group:      "syscalls",
			name:       "sys_exit_execveat",
			tracepoint: objs.TracepointSyscallsSysExitExecveat,
		},
	}

	for _, tp := range tracePoints {
		tp, err := link.Tracepoint(tp.group, tp.name, tp.tracepoint, nil)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		toClose = append(toClose, tp)
	}

	eventBuf, err := ringbuf.NewReader(objs.ExecveEvents)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	bpfEvents := make(chan []byte, 100)
	go func() {
		for {
			rec, err := eventBuf.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Debug("Received signal, exiting..")
					return
				}
				panic(err)
			}

			bpfEvents <- rec.RawSample[:]
		}
	}()

	return &exec{
		objs:      objs,
		eventBuf:  eventBuf,
		lost:      objs.LostCounter,
		toClose:   toClose,
		bpfEvents: bpfEvents,
	}, nil
}

// close will stop reading events off the ring buffer and unload the BPF
// program. The ring buffer is closed as part of the module being closed.
func (e *exec) close() {
	for _, link := range e.toClose {
		if err := link.Close(); err != nil {
			log.Warn(err)
		}
	}

	if err := e.objs.Close(); err != nil {
		log.Warn(err)
	}
}

// events contains raw events off the perf buffer.
func (e *exec) events() <-chan []byte {
	return e.bpfEvents
}
