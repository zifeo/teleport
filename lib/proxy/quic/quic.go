package quic

import (
	"context"
	"net"

	"github.com/gravitational/trace"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/protoadapt"

	clientapi "github.com/gravitational/teleport/api/client/proto"
)

type Client interface {
	Dial(context.Context, *clientapi.DialRequest) (net.Conn, error)
}

type Server interface {
	Accept(context.Context) (PendingConn, error)
}

type PendingConn interface {
	DialRequest() *clientapi.DialRequest

	Accept() (net.Conn, error)
	Reject(msg string) error
}

func NewServer(conn quic.Connection) Server {
	return &server{conn}
}

type server struct {
	conn quic.Connection
}

var _ Server = (*server)(nil)

// Accept implements [Server].
func (s *server) Accept(ctx context.Context) (PendingConn, error) {
	logrus.Infof("---> Server waiting for next stream...")
	stream, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	logrus.Infof("---> Successfully accepted new stream, waiting for dial request...")

	dr := &clientapi.DialRequest{}
	if err := protodelim.UnmarshalFrom(quicvarint.NewReader(stream), protoadapt.MessageV2Of(dr)); err != nil {
		stream.CancelWrite(quic.StreamErrorCode(1))
		stream.CancelRead(quic.StreamErrorCode(1))
		return nil, trace.Wrap(err)
	}

	logrus.Infof("---> Successfully unmarshaled dial request, yielding pending conn.")

	return &pendingConn{
		stream: stream,
		dr:     dr,
	}, nil
}

type pendingConn struct {
	stream quic.Stream
	dr     *clientapi.DialRequest
}

var _ PendingConn = (*pendingConn)(nil)

// DialRequest implements [PendingConn].
func (p *pendingConn) DialRequest() *clientapi.DialRequest {
	return p.dr
}

// Accept implements [PendingConn].
func (p *pendingConn) Accept() (net.Conn, error) {
	logrus.Infof("---> Sending accept msg for pending conn...")
	if _, err := protodelim.MarshalTo(p.stream, &status.Status{
		Code: int32(code.Code_OK),
	}); err != nil {
		p.stream.CancelRead(quic.StreamErrorCode(2))
		p.stream.CancelWrite(quic.StreamErrorCode(2))
		logrus.Warnf("---> Failed to send accept msg for pending conn: %v", err)
		return nil, trace.Wrap(err)
	}

	logrus.Infof("---> Successfully accepted pending conn.")
	return newStreamConn(p.stream, p.dr.GetDestination(), p.dr.GetSource()), nil
}

// Reject implements [PendingConn].
func (p *pendingConn) Reject(msg string) error {
	p.stream.CancelRead(quic.StreamErrorCode(2))

	if _, err := protodelim.MarshalTo(p.stream, &status.Status{
		Code:    int32(code.Code_UNKNOWN),
		Message: msg,
	}); err != nil {
		p.stream.CancelWrite(quic.StreamErrorCode(2))
		return trace.Wrap(err)
	}

	return trace.Wrap(p.stream.Close())
}

func NewClient(conn quic.Connection) Client {
	return &client{conn}
}

type client struct {
	conn quic.Connection
}

var _ Client = (*client)(nil)

// Dial implements [Client].
func (c *client) Dial(ctx context.Context, dr *clientapi.DialRequest) (net.Conn, error) {
	logrus.Infof("---> Client opening stream for new conn...")
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	logrus.Infof("---> Client successfully opened stream, sending dial msg...")
	if _, err := protodelim.MarshalTo(stream, protoadapt.MessageV2Of(dr)); err != nil {
		stream.CancelRead(quic.StreamErrorCode(3))
		stream.CancelWrite(quic.StreamErrorCode(3))
		return nil, trace.Wrap(err)
	}

	logrus.Infof("---> Client successfully sent dial msg, waiting for response...")
	st := &status.Status{}
	if err := protodelim.UnmarshalFrom(quicvarint.NewReader(stream), st); err != nil {
		stream.CancelWrite(quic.StreamErrorCode(4))
		stream.CancelRead(quic.StreamErrorCode(4))
		logrus.Warnf("---> Client failed to recv dial request rsp: %v", err)
		return nil, trace.Wrap(err)
	}

	if st.GetCode() != int32(code.Code_OK) {
		stream.CancelWrite(quic.StreamErrorCode(5))
		stream.CancelRead(quic.StreamErrorCode(5))
		logrus.Warnf("---> Client got non-ok dial attempt response.")
		return nil, trace.Errorf("%s", st)
	}

	logrus.Infof("---> Client got successful dial rsp, returning net.Conn abstraction.")

	return newStreamConn(stream, dr.GetSource(), dr.GetDestination()), nil
}
