package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	pquic "github.com/gravitational/teleport/lib/proxy/quic"
	"github.com/gravitational/teleport/lib/utils"
)

const quicPeerALPN = "teleport-peer"

// QUICServerConfig configures a QUICServer instance.
type QUICServerConfig struct {
	AccessCache   auth.AccessCache
	PacketConn    net.PacketConn
	TLSConfig     *tls.Config
	ClusterDialer ClusterDialer
	Log           logrus.FieldLogger
	ClusterName   string
}

// checkAndSetDefaults checks and sets default values
func (c *QUICServerConfig) checkAndSetDefaults() error {
	if c.Log == nil {
		c.Log = logrus.New()
	}
	c.Log = c.Log.WithField(
		trace.Component,
		teleport.Component(teleport.ComponentProxy, "quicpeer"),
	)

	if c.AccessCache == nil {
		return trace.BadParameter("missing access cache")
	}

	if c.PacketConn == nil {
		return trace.BadParameter("missing packetconn")
	}

	if c.ClusterDialer == nil {
		return trace.BadParameter("missing cluster dialer server")
	}

	if c.ClusterName == "" {
		return trace.BadParameter("missing cluster name")
	}

	if c.TLSConfig == nil {
		return trace.BadParameter("missing tls config")
	}

	if len(c.TLSConfig.Certificates) == 0 {
		return trace.BadParameter("missing tls certificate")
	}

	c.TLSConfig = c.TLSConfig.Clone()
	c.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	c.TLSConfig.NextProtos = []string{quicPeerALPN}
	c.TLSConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if cs.NegotiatedProtocol == "" {
			return errors.New("ALPN is required")
		}
		return nil
	}
	c.TLSConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		cfg := c.TLSConfig.Clone()
		// refresh ClientCAs on every incoming connection
		if pool, err := getCertPool(c.AccessCache, c.ClusterName); err != nil {
			c.Log.WithError(err).Error("Failed to retrieve client CA pool.")
		} else {
			cfg.ClientCAs = pool
		}
		return cfg, nil
	}
	return nil
}

// QUICServer is a proxy service server using grpc and tls.
type QUICServer struct {
	cfg      QUICServerConfig
	listener *quic.Listener

	served chan struct{}
	wg     sync.WaitGroup
}

// NewServer creates a new proxy server instance.
func NewQUICServer(cfg QUICServerConfig) (*QUICServer, error) {
	err := cfg.checkAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	transport := &quic.Transport{Conn: cfg.PacketConn}
	listener, err := transport.Listen(cfg.TLSConfig, &quic.Config{
		MaxIdleTimeout:  time.Minute,
		KeepAlivePeriod: 20 * time.Second,

		MaxIncomingUniStreams: -1,
		MaxIncomingStreams:    1 << 60,

		MaxStreamReceiveWindow:     quicvarint.Max,
		MaxConnectionReceiveWindow: quicvarint.Max,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &QUICServer{
		cfg:      cfg,
		listener: listener,
	}, nil
}

// Serve runs the proxy server.
func (s *QUICServer) Serve() error {
	defer close(s.served)
	for {
		conn, err := s.listener.Accept(context.TODO())
		if err != nil {
			return trace.Wrap(err)
		}

		s.wg.Add(1)
		go func() {
			s.wg.Done()
			err := s.handleConn(context.TODO(), conn)
			if err != nil {
				s.cfg.Log.WithError(err).Warn("Handling connection.")
			}
		}()
	}
}

func (s *QUICServer) handleConn(ctx context.Context, conn quic.Connection) error {
	defer conn.CloseWithError(0, "done")

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return trace.Wrap(err)
		}

		s.wg.Add(1)
		go func() {
			s.wg.Done()
			err := s.handleStream(ctx, stream)
			if err != nil {
				s.cfg.Log.WithError(err).Warn("Handling stream.")
			}
		}()
	}
}

func (s *QUICServer) handleStream(ctx context.Context, stream quic.Stream) error {
	conn, err := pquic.NewPendingConn(stream)
	if err != nil {
		return trace.Wrap(err)
	}

	req := conn.DialRequest()

	if req == nil {
		conn.Reject("invalid dial request: request must not be nil")
		return trace.BadParameter("invalid dial request: request must not be nil")
	}

	if req.Source == nil || req.Destination == nil {
		conn.Reject("invalid dial request: source and destination must not be nil")
		return trace.BadParameter("invalid dial request: source and destination must not be nil")
	}

	log := s.cfg.Log.WithFields(logrus.Fields{
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

	targetConn, err := s.cfg.ClusterDialer.Dial(clusterName, DialParams{
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

// Close closes the proxy server immediately.
func (s *QUICServer) Close() error {
	s.cfg.PacketConn.Close()
	return trace.Wrap(s.Shutdown())
}

func (s *QUICServer) Shutdown() error {
	<-s.served
	s.listener.Close()
	s.wg.Wait()
	return nil
}
