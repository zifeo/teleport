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

package peer

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/gravitational/trace"
	quicgo "github.com/quic-go/quic-go"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	streamutils "github.com/gravitational/teleport/api/utils/grpc/stream"
	"github.com/gravitational/teleport/lib/proxy/quic"
	"github.com/gravitational/teleport/lib/utils"
)

type connection struct {
	req                 *proto.DialRequest
	stream              proto.ProxyService_DialNodeServer
	source, destination net.Addr
	closed              chan error
	once                sync.Once
}

func (c *connection) DialRequest() *proto.DialRequest {
	return c.req
}

func (c *connection) Accept() (net.Conn, error) {
	err := c.stream.Send(&proto.Frame{
		Message: &proto.Frame_ConnectionEstablished{
			ConnectionEstablished: &proto.ConnectionEstablished{},
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	streamRW, err := streamutils.NewReadWriter(frameStream{stream: c.stream})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &connCloser{c: c, Conn: utils.NewTrackingConn(streamutils.NewConn(streamRW, c.source, c.destination))}, nil
}

func (c *connection) Reject(msg string) error {
	c.close(msg)
	return nil
}

func (c *connection) close(msg string) {
	c.once.Do(func() {
		c.closed <- errors.New(msg)
		close(c.closed)
	})
}

type connCloser struct {
	net.Conn
	c *connection
}

func (c *connCloser) Close() error {
	c.c.close("")
	return trace.Wrap(c.Conn.Close())
}

// ProxyService implements the grpc ProxyService.
type ProxyService struct {
	clusterDialer ClusterDialer
	connC         chan *connection
}

func NewProxyService(dialer ClusterDialer) (*ProxyService, error) {
	if dialer == nil {
		return nil, trace.BadParameter("missing cluster dialer")
	}

	return &ProxyService{
		clusterDialer: dialer,
		connC:         make(chan *connection, 100),
	}, nil
}

// DialNode opens a bidirectional stream to the requested node.
func (s *ProxyService) DialNode(stream proto.ProxyService_DialNodeServer) error {
	frame, err := stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}

	conn := &connection{
		req:    frame.GetDialRequest(),
		stream: stream,
		closed: make(chan error),
	}

	s.connC <- conn

	select {
	case <-stream.Context().Done():
		return nil
	case err := <-conn.closed:
		return trace.Wrap(err)
	}
}

func (p *ProxyService) Accept(ctx context.Context) (quic.PendingConn, error) {
	select {
	case c := <-p.connC:
		return c, nil
	case <-ctx.Done():
		return nil, trace.Wrap(ctx.Err())
	}
}

// splitServerID splits a server id in to a node id and cluster name.
func splitServerID(address string) (string, string, error) {
	split := strings.Split(address, ".")
	if len(split) == 0 || split[0] == "" {
		return "", "", trace.BadParameter("invalid server id: \"%s\"", address)
	}

	return split[0], strings.Join(split[1:], "."), nil
}

// ClusterDialer dials a node in the given cluster.
type ClusterDialer interface {
	Dial(clusterName string, request DialParams) (net.Conn, error)
}

type DialParams struct {
	From     *utils.NetAddr
	To       *utils.NetAddr
	ServerID string
	ConnType types.TunnelType
}

type QuicService struct {
	PendingC chan quic.PendingConn
}

func (q *QuicService) Handle(ctx context.Context, qconn quicgo.Connection) {
	srv := quic.NewServer(qconn)
	for {
		pconn, err := srv.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || utils.IsUseOfClosedNetworkError(err) {
				return
			}
			continue
		}

		q.PendingC <- pconn
	}
}

func (q *QuicService) Accept(ctx context.Context) (quic.PendingConn, error) {
	return <-q.PendingC, nil
}
