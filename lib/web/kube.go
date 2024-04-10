package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	clientproto "github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/session"
)

type podHandler struct {
	cluster           string
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
		t.sendError(err)
		return
	}

	envelope := &Envelope{
		Version: defaults.WebsocketVersion,
		Type:    defaults.WebsocketSessionMetadata,
		Payload: string(sessionMetadataResponse),
	}

	envelopeBytes, err := proto.Marshal(envelope)
	if err != nil {
		t.sendError(err)
		return
	}

	err = t.ws.WriteMessage(websocket.BinaryMessage, envelopeBytes)
	if err != nil {
		t.sendError(err)
		return
	}
}

func (t *podHandler) Close() error {
	return trace.Wrap(t.ws.Close())
}

func (t *podHandler) sendError(err error) {
	envelope := &Envelope{
		Version: defaults.WebsocketVersion,
		Type:    defaults.WebsocketError,
		Payload: err.Error(),
	}

	envelopeBytes, err := proto.Marshal(envelope)
	if err != nil {
		t.log.WithError(err).Error("failed to marshal error message")
	}
	if err := t.ws.WriteMessage(websocket.BinaryMessage, envelopeBytes); err != nil {
		t.log.WithError(err).Error("failed to send error message")
	}
}

func (t *podHandler) handler(r *http.Request) {
	t.log.Debug("Creating websocket stream")

	// Start sending ping frames through websocket to the client.
	go startPingLoop(r.Context(), t.ws, t.keepAliveInterval, t.log, t.Close)

	_, err := t.userClient.GenerateUserCerts(r.Context(), clientproto.UserCertsRequest{
		PublicKey:         t.sctx.cfg.Session.GetPub(),
		Username:          t.sctx.GetUser(),
		Expires:           t.sctx.cfg.Session.GetExpiryTime(),
		Format:            constants.CertificateFormatStandard,
		RouteToCluster:    t.cluster,
		KubernetesCluster: t.req.Cluster,
		Usage:             clientproto.UserCertsRequest_Kubernetes,
	})
	if err != nil {
		t.log.WithError(err).Warn("Failed creating user certs")
		t.sendError(err)
		return
	}

}
