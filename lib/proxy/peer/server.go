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
	"time"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/proxy/quic"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	peerKeepAlive = time.Second * 10
	peerTimeout   = time.Second * 20
)

// ServerConfig configures a Server instance.
type ServerConfig struct {
	Log           logrus.FieldLogger
	ClusterDialer ClusterDialer

	Server quic.Server
}

// checkAndSetDefaults checks and sets default values
func (c *ServerConfig) checkAndSetDefaults() error {
	if c.Log == nil {
		c.Log = logrus.New()
	}
	c.Log = c.Log.WithField(
		trace.Component,
		teleport.Component(teleport.ComponentProxy, "peer"),
	)

	if c.ClusterDialer == nil {
		return trace.BadParameter("missing cluster dialer")
	}

	if c.Server == nil {
		return trace.BadParameter("missing server")
	}

	return nil
}

// Server is a proxy service server using grpc and tls.
type Server struct {
	config ServerConfig
}

// NewServer creates a new proxy server instance.
func NewServer(config ServerConfig) (*Server, error) {
	if err := config.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &Server{
		config: config,
	}, nil
}

// Serve starts the proxy server.
func (s *Server) Serve(ctx context.Context) error {
	for {
		pconn, err := s.config.Server.Accept(ctx)
		switch {
		case err == nil:
			go func() {
				if err := s.handleConn(ctx, pconn); err != nil {
					s.config.Log.WithError(err).Debug("connection terminated")
				}
			}()
		case errors.Is(err, context.Canceled) || utils.IsUseOfClosedNetworkError(err):
			return nil
		default:
			s.config.Log.WithError(err).Warn("failed to accept inbound connection")
		}
	}
}

func (s *Server) handleConn(ctx context.Context, conn quic.PendingConn) error {
	req := conn.DialRequest()

	if req == nil {
		conn.Reject("invalid dial request: request must not be nil")
		return trace.BadParameter("invalid dial request: request must not be nil")
	}

	if req.Source == nil || req.Destination == nil {
		conn.Reject("invalid dial request: source and destination must not be nil")
		return trace.BadParameter("invalid dial request: source and destination must not be nil")
	}

	log := s.config.Log.WithFields(logrus.Fields{
		"node": req.NodeID,
		"src":  req.Source.Addr,
		"dst":  req.Destination.Addr,
	})
	log.Debug("Received dial request from peer.")

	_, clusterName, err := splitServerID(req.NodeID)
	if err != nil {
		conn.Reject(err.Error())
		return trace.Wrap(err)
	}

	source := &utils.NetAddr{
		Addr:        req.Source.Addr,
		AddrNetwork: req.Source.Network,
	}
	destination := &utils.NetAddr{
		Addr:        req.Destination.Addr,
		AddrNetwork: req.Destination.Network,
	}

	targetConn, err := s.config.ClusterDialer.Dial(clusterName, DialParams{
		From:     source,
		To:       destination,
		ServerID: req.NodeID,
		ConnType: req.TunnelType,
	})
	if err != nil {
		conn.Reject(err.Error())
		return trace.Wrap(err)
	}

	clientConn, err := conn.Accept()
	if err != nil {
		conn.Reject(err.Error())
		return trace.Wrap(err, targetConn.Close())
	}

	return trace.Wrap(utils.ProxyConn(ctx, clientConn, targetConn))
}
