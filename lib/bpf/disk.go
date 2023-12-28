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
	"io"
	"runtime"

	"github.com/gravitational/trace"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/observability/metrics"
)

var (
	lostDiskEvents = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: teleport.MetricLostDiskEvents,
			Help: "Number of lost disk events.",
		},
	)
)

const (
	diskEventsBuffer = "open_events"
)

// rawOpenEvent is sent by the eBPF program that Teleport pulls off the perf
// buffer.
type rawOpenEvent struct {
	// CgroupID is the internal cgroupv2 ID of the event.
	CgroupID uint64

	// PID is the ID of the process.
	PID uint64

	// ReturnCode is the return code of open.
	ReturnCode int32

	// Command is name of the executable opening the file.
	Command [CommMax]byte

	// Path is the full path to the file being opened.
	Path [PathMax]byte

	// Flags are the flags passed to open.
	Flags int32
}

type cgroupRegister interface {
	startSession(cgroupID uint64) error
	endSession(cgroupID uint64) error
}

type open struct {
	//session

	objs diskObjects

	eventBuf chan []byte
	toClose  []io.Closer
	lost     *Counter
}

// startOpen will compile, load, start, and pull events off the perf buffer
// for the BPF program.
func startOpen(bufferSize int) (*open, error) {
	err := metrics.RegisterPrometheusCollectors(lostDiskEvents)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var objs diskObjects
	if err := loadDiskObjects(&objs, nil); err != nil {
		return nil, trace.Wrap(err)
	}

	trs := []struct {
		name string
		prog *ebpf.Program
	}{
		{
			name: "sys_enter_creat",
			prog: objs.TracepointSyscallsSysEnterCreat,
		},
		{
			name: "sys_enter_open",
			prog: objs.TracepointSyscallsSysEnterOpen,
		},
		{
			name: "sys_enter_openat",
			prog: objs.TracepointSyscallsSysEnterOpenat,
		},
		{
			name: "sys_exit_creat",
			prog: objs.TracepointSyscallsSysExitCreat,
		},
		{
			name: "sys_exit_open",
			prog: objs.TracepointSyscallsSysExitOpen,
		},
		{
			name: "sys_exit_openat",
			prog: objs.TracepointSyscallsSysExitOpenat,
		},
	}

	if runtime.GOARCH != "arm64" {
		// creat is not implemented on arm64.
		trs = append(trs, []struct {
			name string
			prog *ebpf.Program
		}{
			{
				name: "sys_enter_openat2",
				prog: objs.TracepointSyscallsSysEnterOpenat2,
			},
			{
				name: "sys_exit_openat2",
				prog: objs.TracepointSyscallsSysExitOpenat2,
			},
		}...)
	}

	toClose := make([]io.Closer, 0, len(trs))
	for _, tr := range trs {
		tp, err := link.Tracepoint("syscalls", tr.name, tr.prog, nil)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		toClose = append(toClose, tp)
	}

	eventBuf, err := ringbuf.NewReader(objs.OpenEvents)
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

	return &open{
		objs:     objs,
		eventBuf: bpfEvents,
	}, nil
}

func (o *open) startSession(cgroupID uint64) error {
	if err := o.objs.MonitoredCgroups.Put(cgroupID, int64(0)); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (o *open) endSession(cgroupID uint64) error {
	if err := o.objs.MonitoredCgroups.Delete(&cgroupID); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// close will stop reading events off the ring buffer and unload the BPF
// program. The ring buffer is closed as part of the module being closed.
func (o *open) close() {
	for _, toClose := range o.toClose {
		if err := toClose.Close(); err != nil {
			log.Warn(err)
		}
	}

	if err := o.objs.Close(); err != nil {
		log.Warn(err)
	}
}

// events contains raw events off the perf buffer.
func (o *open) events() <-chan []byte {
	return o.eventBuf
}
