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
	lostNetworkEvents = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: teleport.MetricLostNetworkEvents,
			Help: "Number of lost network events.",
		},
	)
)

const (
	network4EventsBuffer = "ipv4_events"
	network6EventsBuffer = "ipv6_events"
)

// rawConn4Event is sent by the eBPF program that Teleport pulls off the perf
// buffer.
type rawConn4Event struct {
	// CgroupID is the internal cgroupv2 ID of the event.
	CgroupID uint64

	// Version is the version of TCP (4 or 6).
	Version uint64

	// PID is the process ID.
	PID uint32

	// SrcAddr is the source IP address.
	SrcAddr uint32

	// DstAddr is the destination IP address.
	DstAddr uint32

	// DstPort is the port the connection is being made to.
	DstPort uint16

	// Command is name of the executable making the connection.
	Command [CommMax]byte
}

// rawConn6Event is sent by the eBPF program that Teleport pulls off the perf
// buffer.
type rawConn6Event struct {
	// CgroupID is the internal cgroupv2 ID of the event.
	CgroupID uint64

	// Version is the version of TCP (4 or 6).
	Version uint64

	// PID is the process ID.
	PID uint32

	// SrcAddr is the source IP address.
	SrcAddr [4]uint32

	// DstAddr is the destination IP address.
	DstAddr [4]uint32

	// DstPort is the port the connection is being made to.
	DstPort uint16

	// Command is name of the executable making the connection.
	Command [CommMax]byte
}

type conn struct {
	//session
	objs *networkObjects

	event4Chan chan []byte
	event6Chan chan []byte
	toClose    []interface{ Close() error }

	//lost *Counter
}

func startConn(bufferSize int) (*conn, error) {
	err := metrics.RegisterPrometheusCollectors(lostNetworkEvents)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, trace.WrapWithMessage(err, "Removing memlock")
	}

	var objs networkObjects
	if err := loadNetworkObjects(&objs, nil); err != nil {
		return nil, trace.Wrap(err)
	}

	kprobes := []struct {
		symbol string
		prog   *ebpf.Program
	}{
		{
			symbol: "tcp_v4_connect",
			prog:   objs.KprobeTcpV4Connect,
		},
		{
			symbol: "tcp_v6_connect",
			prog:   objs.KprobeTcpV6Connect,
		},
	}

	kretProbes := []struct {
		symbol string
		prog   *ebpf.Program
	}{
		{
			symbol: "tcp_v4_connect",
			prog:   objs.KretprobeTcpV4Connect,
		},
		{
			symbol: "tcp_v6_connect",
			prog:   objs.KretprobeTcpV6Connect,
		},
	}

	toClose := make([]interface{ Close() error }, 0)
	for _, kprobe := range kprobes {
		kp, err := link.Kprobe(kprobe.symbol, kprobe.prog, nil)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		toClose = append(toClose, kp)
	}

	for _, kretprobe := range kretProbes {
		kret, err := link.Kretprobe(kretprobe.symbol, kretprobe.prog, nil)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		toClose = append(toClose, kret)
	}

	eventBuf, err := ringbuf.NewReader(objs.Ipv4Events)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	bpfEvents := make(chan []byte, 100)
	go func() {
		for {
			event, err := eventBuf.Read()
			if err != nil {
				return
			}
			bpfEvents <- event.RawSample
		}
	}()

	return &conn{
		objs:       &objs,
		event4Chan: bpfEvents,
		event6Chan: make(chan []byte, 100),
		toClose:    toClose,
	}, nil
}

func (c *conn) startSession(cgroupID uint64) error {
	if err := c.objs.MonitoredCgroups.Put(cgroupID, int64(0)); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (c *conn) endSession(cgroupID uint64) error {
	if err := c.objs.MonitoredCgroups.Delete(&cgroupID); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// close will stop reading events off the ring buffer and unload the BPF
// program. The ring buffer is closed as part of the module being closed.
func (c *conn) close() {
	//c.lost.Close()

	for _, link := range c.toClose {
		if err := link.Close(); err != nil {
			log.Warn(err)
		}
	}

	if err := c.objs.Close(); err != nil {
		log.Warn(err)
	}
}

// v4Events contains raw events off the perf buffer.
func (c *conn) v4Events() <-chan []byte {
	return c.event4Chan
}

// v6Events contains raw events off the perf buffer.
func (c *conn) v6Events() <-chan []byte {
	return c.event6Chan
}
