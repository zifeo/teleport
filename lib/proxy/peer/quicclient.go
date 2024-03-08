package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport"
	clientapi "github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	pquic "github.com/gravitational/teleport/lib/proxy/quic"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
)

type ClientI interface {
	DialNode(proxyIDs []string, nodeID string, src, dst net.Addr, tunnelType types.TunnelType) (net.Conn, error)

	GetConnectionsCount() int

	Stop() error
	Shutdown()
}

// QUICClientConfig configures a QUICClient instance.
type QUICClientConfig struct {
	// Context is a signaling context
	Context context.Context
	// ID is the ID of this server proxy
	ID string
	// AccessPoint is a caching auth client
	AccessPoint auth.ProxyAccessPoint
	// TLSConfig is the proxy client TLS configuration.
	TLSConfig *tls.Config
	// Log is the proxy client logger.
	Log logrus.FieldLogger
	// Clock is used to control connection monitoring ticker.
	Clock clockwork.Clock
	// GracefulShutdownTimout is used set the graceful shutdown
	// duration limit.
	GracefulShutdownTimeout time.Duration
	// ClusterName is the name of the cluster.
	ClusterName string
}

// checkAndSetDefaults checks and sets default values
func (c *QUICClientConfig) checkAndSetDefaults() error {
	if c.Log == nil {
		c.Log = logrus.New()
	}

	c.Log = c.Log.WithField(
		trace.Component,
		teleport.Component("proxy", "quicpeer"),
	)

	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}

	if c.Context == nil {
		c.Context = context.Background()
	}

	if c.GracefulShutdownTimeout == 0 {
		c.GracefulShutdownTimeout = defaults.DefaultGracefulShutdownTimeout
	}

	if c.ID == "" {
		return trace.BadParameter("missing parameter ID")
	}

	if c.AccessPoint == nil {
		return trace.BadParameter("missing access cache")
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

	return nil
}

// clientQUICConn hold info about a dialed grpc connection
type clientQUICConn struct {
	conn          quic.Connection
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	stopAfterFunc func() bool
	id            string
	addr          string
}

// QUICClient is a peer proxy service client using grpc and tls.
type QUICClient struct {
	sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	config  QUICClientConfig
	conns   map[string]*clientQUICConn
	metrics *clientMetrics
}

// NewQUICClient creats a new peer proxy client.
func NewQUICClient(config QUICClientConfig) (*QUICClient, error) {
	err := config.checkAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	metrics, err := newClientMetrics()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	closeContext, cancel := context.WithCancel(config.Context)

	c := &QUICClient{
		config:  config,
		ctx:     closeContext,
		cancel:  cancel,
		conns:   make(map[string]*clientQUICConn),
		metrics: metrics,
	}

	go c.sync()

	return c, nil
}

// sync runs the peer proxy watcher functionality.
func (c *QUICClient) sync() {
	proxyWatcher, err := services.NewProxyWatcher(c.ctx, services.ProxyWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: teleport.Component(teleport.ComponentProxyPeer),
			Client:    c.config.AccessPoint,
			Log:       c.config.Log,
		},
		ProxyDiffer: func(old, new types.Server) bool {
			return old.GetPeerAddr() != new.GetPeerAddr()
		},
	})
	if err != nil {
		c.config.Log.Errorf("Error initializing proxy peer watcher: %+v.", err)
		return
	}
	defer proxyWatcher.Close()

	for {
		select {
		case <-c.ctx.Done():
			c.config.Log.Debug("Stopping peer proxy sync: context done.")
			return
		case <-proxyWatcher.Done():
			c.config.Log.Debug("Stopping peer proxy sync: proxy watcher done.")
			return
		case proxies := <-proxyWatcher.ProxiesC:
			if err := c.updateConnections(proxies); err != nil {
				c.config.Log.Errorf("Error syncing peer proxies: %+v.", err)
			}
		}
	}
}

func (c *QUICClient) updateConnections(proxies []types.Server) error {
	c.RLock()
	toDial := make(map[string]string)
	for _, proxy := range proxies {
		id, addr := proxy.GetName(), proxy.GetPeerAddr()
		if id == c.config.ID {
			continue
		}
		conn := c.conns[id]
		if conn != nil && conn.addr == addr {
			continue
		}
		toDial[id] = addr
	}
	c.RUnlock()

	newConns := make(map[string]*clientQUICConn, len(toDial))
	var lastDialErr error
	for id, addr := range toDial {
		conn, err := c.connect(id, addr)
		if err != nil {
			c.metrics.reportTunnelError(errorProxyPeerTunnelDial)
			c.config.Log.Debugf("Error dialing peer proxy %+v at %+v", id, addr)
			lastDialErr = err
			continue
		}
		newConns[id] = conn
	}

	c.Lock()
	for id, conn := range newConns {
		oldConn := c.conns[id]
		c.conns[id] = conn
		conn.stopAfterFunc = context.AfterFunc(conn.conn.Context(), func() {
			c.Lock()
			if c.conns[id] == conn {
				delete(c.conns, id)
			}
			c.Unlock()
		})
		newConns[id] = oldConn
		if oldConn != nil {
			oldConn.stopAfterFunc()
		}
	}
	c.Unlock()

	for _, conn := range newConns {
		if conn == nil {
			continue
		}
		conn.stopAfterFunc()
		go c.shutdownConn(conn)
	}

	return lastDialErr
}

// DialNode dials a node through a peer proxy.
func (c *QUICClient) DialNode(
	proxyIDs []string,
	nodeID string,
	src net.Addr,
	dst net.Addr,
	tunnelType types.TunnelType,
) (net.Conn, error) {
	return c.dial(proxyIDs, &clientapi.DialRequest{
		NodeID:     nodeID,
		TunnelType: tunnelType,
		Source: &clientapi.NetAddr{
			Addr:    src.String(),
			Network: src.Network(),
		},
		Destination: &clientapi.NetAddr{
			Addr:    dst.String(),
			Network: dst.Network(),
		},
	})
}

// Shutdown gracefully shuts down all existing client connections.
func (c *QUICClient) Shutdown() {
	c.Lock()
	defer c.Unlock()

	var wg sync.WaitGroup
	for _, conn := range c.conns {
		wg.Add(1)
		go func(conn *clientQUICConn) {
			defer wg.Done()

			timeoutCtx, cancel := context.WithTimeout(context.Background(), c.config.GracefulShutdownTimeout)
			defer cancel()

			go func() {
				if err := c.shutdownConn(conn); err != nil {
					c.config.Log.Infof("proxy peer connection %+v graceful shutdown error: %+v", conn.id, err)
				}
			}()

			select {
			case <-conn.ctx.Done():
			case <-timeoutCtx.Done():
				if err := c.stopConn(conn); err != nil {
					c.config.Log.Infof("proxy peer connection %+v close error: %+v", conn.id, err)
				}
			}
		}(conn)
	}
	wg.Wait()
	c.cancel()
}

// Stop closes all existing client connections.
func (c *QUICClient) Stop() error {
	c.Lock()
	defer c.Unlock()

	var errs []error
	for _, conn := range c.conns {
		if err := c.stopConn(conn); err != nil {
			errs = append(errs, err)
		}
	}
	c.cancel()
	return trace.NewAggregate(errs...)
}

func (c *QUICClient) GetConnectionsCount() int {
	c.RLock()
	defer c.RUnlock()
	return len(c.conns)
}

// shutdownConn gracefully shuts down a clientQUICConn by waiting for open
// streams to finish.
func (c *QUICClient) shutdownConn(conn *clientQUICConn) error {
	conn.wg.Wait() // wait for streams to gracefully end
	conn.cancel()
	return conn.conn.CloseWithError(0, "shutdownConn")
}

// stopConn immediately closes a clientQUICConn.
func (c *QUICClient) stopConn(conn *clientQUICConn) error {
	conn.cancel()
	return conn.conn.CloseWithError(0, "stopConn")
}

func (c *QUICClient) dial(proxyIDs []string, dialRequest *clientapi.DialRequest) (net.Conn, error) {
	conns, err := c.getConnections(proxyIDs)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var errs []error
	for _, conn := range conns {
		dialer := pquic.NewDialer(conn.conn)
		c, err := dialer.Dial(c.ctx, dialRequest)
		if err == nil {
			return c, nil
		}

		errs = append(errs, trace.Wrap(err))
	}

	return nil, trace.NewAggregate(errs...)
}

// getConnections returns connections to the supplied proxy ids.
func (c *QUICClient) getConnections(proxyIDs []string) ([]*clientQUICConn, error) {
	if len(proxyIDs) == 0 {
		return nil, trace.BadParameter("failed to dial: no proxy ids given")
	}

	ids := make(map[string]struct{})
	var conns []*clientQUICConn

	// look for existing matching connections.
	c.RLock()
	for _, id := range proxyIDs {
		ids[id] = struct{}{}

		conn, ok := c.conns[id]
		if !ok {
			continue
		}

		conns = append(conns, conn)
	}
	c.RUnlock()

	if len(conns) != 0 {
		rand.Shuffle(len(conns), func(i, j int) {
			conns[i], conns[j] = conns[j], conns[i]
		})
		return conns, nil
	}

	c.metrics.reportTunnelError(errorProxyPeerTunnelNotFound)
	return nil, trace.ConnectionProblem(nil, "Proxies not found.")
}

// connect dials a new connection to proxyAddr.
func (c *QUICClient) connect(peerID string, peerAddr string) (*clientQUICConn, error) {
	tlsConfig, err := getConfigForServer(c.config.TLSConfig, c.config.AccessPoint, c.config.Log, c.config.ClusterName)()
	if err != nil {
		return nil, trace.Wrap(err, "Error updating client tls config")
	}

	tlsConfig.NextProtos = []string{quicPeerALPN}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) (err error) {
		if state.NegotiatedProtocol == "" {
			return errors.New("ALPN is required")
		}

		// VerifiedChains must be populated after the handshake.
		if len(state.VerifiedChains) < 1 || len(state.VerifiedChains[0]) < 1 {
			return trace.Errorf("missing expected certificate chains")
		}

		identity, err := tlsca.FromSubject(
			state.VerifiedChains[0][0].Subject,
			state.VerifiedChains[0][0].NotAfter,
		)
		if err != nil {
			return trace.Wrap(err)
		}

		// verify that we've connected to a proxy
		if err := checkProxyRole(identity); err != nil {
			return trace.Wrap(err)
		}

		const duplicatePeerMsg = "Detected multiple Proxy Peers with the same public address %q when connecting to Proxy %q which can lead to inconsistent state and problems establishing sessions. For best results ensure that `peer_public_addr` is unique per proxy and not a load balancer."

		// verify that we hit the proxy with the expected ID
		if err := validatePeer(auth.HostFQDN(peerID, c.config.ClusterName), identity); err != nil {
			c.config.Log.Errorf(duplicatePeerMsg, peerAddr, peerID)
			return trace.Wrap(err)
		}

		return nil
	}

	connCtx, cancel := context.WithCancel(c.ctx)
	conn, err := quic.DialAddr(connCtx, peerAddr, tlsConfig, &quic.Config{
		MaxIdleTimeout:  time.Minute,
		KeepAlivePeriod: 20 * time.Second,

		MaxIncomingUniStreams: -1,
		MaxIncomingStreams:    -1,

		MaxStreamReceiveWindow:     quicvarint.Max,
		MaxConnectionReceiveWindow: quicvarint.Max,
	})
	if err != nil {
		cancel()
		return nil, trace.Wrap(err)
	}

	return &clientQUICConn{
		conn:   conn,
		ctx:    connCtx,
		cancel: cancel,
		id:     peerID,
		addr:   peerAddr,
	}, nil
}
