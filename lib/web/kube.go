package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/remotecommand"

	clientproto "github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	proxy2 "github.com/gravitational/teleport/lib/kube/proxy"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"
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
	publicProxyAddr   string
	localAccessPoint  localAccessPoint
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

	pk, err := keys.ParsePrivateKey(t.sctx.cfg.Session.GetPriv())
	if err != nil {
		t.log.WithError(err).Warn("Failed getting private key")
		return
	}
	key := &client.Key{
		PrivateKey: pk,
		Cert:       t.sctx.cfg.Session.GetPub(),
		TLSCert:    t.sctx.cfg.Session.GetTLSCert(),
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	CACert, err := t.localAccessPoint.GetCertAuthority(ctx, types.CertAuthID{
		Type:       types.UserCA,
		DomainName: t.cluster,
	}, false)
	_ = CACert
	if err != nil {
		t.log.WithError(err).Warn("Failed getting private key")
		return
	}

	cert, err := t.userClient.GenerateUserCerts(r.Context(), clientproto.UserCertsRequest{
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

	rsaKey, err := key.PrivateKey.RSAPrivateKeyPEM()
	if err != nil {
		t.log.WithError(err).Warn("Failed getting rsa private key")
		return
	}

	cfg := clientcmdapi.Config{
		Clusters:  make(map[string]*clientcmdapi.Cluster),
		AuthInfos: make(map[string]*clientcmdapi.AuthInfo),
		Contexts:  make(map[string]*clientcmdapi.Context),
	}

	host, _, err := utils.SplitHostPort(t.publicProxyAddr)
	if err != nil {
		t.log.WithError(err).Warn("Failed splitting public proxy address")
		return
	}
	cfg.Clusters["cluster1"] = &clientcmdapi.Cluster{
		Server:                t.publicProxyAddr,
		InsecureSkipTLSVerify: true,
		TLSServerName:         fmt.Sprintf("%s.%s", constants.KubeTeleportProxyALPNPrefix, host),
	}
	cfg.AuthInfos["user1"] = &clientcmdapi.AuthInfo{
		ClientCertificateData: cert.TLS,
		ClientKeyData:         rsaKey,
	}
	cfg.Contexts["context1"] = &clientcmdapi.Context{
		Cluster:  "cluster1",
		AuthInfo: "user1",
	}
	cfg.APIVersion = "v1"
	cfg.CurrentContext = "context1"
	config, err := clientcmd.NewDefaultClientConfig(cfg, nil).ClientConfig()

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.log.Error(err)
		return
	}

	cmd := []string{"sh"}
	req := kubeClient.CoreV1().RESTClient().Post().Resource("pods").Name(t.req.Pod).
		Namespace(t.req.Namespace).SubResource("exec")
	option := &v1.PodExecOptions{
		Command: cmd,
		Stdin:   true,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}

	req.VersionedParams(
		option,
		scheme.ParameterCodec,
	)
	t.log.Debugf("Request URL: %s", req.URL())

	wsExec, err := remotecommand.NewWebSocketExecutor(config, "POST", req.URL().String())
	if err != nil {
		t.log.Error(err)
		return
	}

	stream := NewTerminalStream(ctx, TerminalStreamConfig{WS: t.ws, Logger: t.log})

	stderrStream := stderrWriter{stream: stream}
	err = wsExec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdin:  &proxy2.IOLogger{Name: "term_stdin", Reader: stream, Writer: stream, Closer: stream},
		Stdout: &proxy2.IOLogger{Name: "term_stdout", Reader: stream, Writer: stream, Closer: stream},
		Stderr: &proxy2.IOLogger{Name: "term_stderr", Reader: stream, Writer: stderrStream, Closer: stream},
		Tty:    true,
	})
	if err != nil {
		t.log.Error(err)
		return
	}
}
