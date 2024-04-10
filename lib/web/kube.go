package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/session"
)

type podHandler struct {
	req               PodExecRequest
	sess              session.Session
	sctx              *SessionContext
	ws                *websocket.Conn
	keepAliveInterval time.Duration
	log               *logrus.Entry
	userClient        auth.ClientI
}

func (t *podHandler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	// Allow closing websocket if the user logs out before exiting
	// the session.
	t.sctx.AddClosers(t)
	defer t.sctx.RemoveCloser(t)

	sessionMetadataResponse, err := json.Marshal(siteSessionGenerateResponse{Session: t.sess})
	if err != nil {
		t.sendError("unable to marshal session response", err, t.ws)
		return
	}

	envelope := &Envelope{
		Version: defaults.WebsocketVersion,
		Type:    defaults.WebsocketSessionMetadata,
		Payload: string(sessionMetadataResponse),
	}

	envelopeBytes, err := proto.Marshal(envelope)
	if err != nil {
		t.sendError("unable to marshal session data event for web client", err, t.ws)
		return
	}

	err = t.ws.WriteMessage(websocket.BinaryMessage, envelopeBytes)
	if err != nil {
		t.sendError("unable to write message to socket", err, t.ws)
		return
	}
}

func (t *podHandler) Close() error {
	return trace.Wrap(t.ws.Close())
}

func (t *podHandler) sendError(errMsg string, err error, ws WSConn) {
	envelope := &Envelope{
		Version: defaults.WebsocketVersion,
		Type:    defaults.WebsocketError,
		Payload: fmt.Sprintf("%s: %s", errMsg, err.Error()),
	}

	envelopeBytes, err := proto.Marshal(envelope)
	if err != nil {
		t.log.WithError(err).Error("failed to marshal error message")
	}
	if err := ws.WriteMessage(websocket.BinaryMessage, envelopeBytes); err != nil {
		t.log.WithError(err).Error("failed to send error message")
	}
}

func (t *podHandler) handler(r *http.Request) {
	t.log.Debug("Creating websocket stream")

	// Start sending ping frames through websocket to the client.
	go startPingLoop(r.Context(), t.ws, t.keepAliveInterval, t.log, t.Close)

}
