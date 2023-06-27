// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !windows

package benchmark

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
	"github.com/gravitational/roundtrip"
	"github.com/gravitational/trace"
	"golang.org/x/net/context"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/web"
)

// connectToHost opens an SSH session to the target host via the Proxy web api.
func connectToHost(ctx context.Context, tc *client.TeleportClient, webSession *webSession, host string) (io.ReadWriteCloser, error) {
	req := web.TerminalRequest{
		Server: host,
		Login:  tc.HostLogin,
		Term: session.TerminalParams{
			W: 100,
			H: 100,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	u := url.URL{
		Host:   tc.WebProxyAddr,
		Scheme: client.WSS,
		Path:   fmt.Sprintf("/v1/webapi/sites/%v/connect", tc.SiteName),
		RawQuery: url.Values{
			"params":                        []string{string(data)},
			roundtrip.AccessTokenQueryParam: []string{webSession.getToken()},
		}.Encode(),
	}

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: tc.InsecureSkipVerify},
		Jar:             webSession.getCookieJar(),
	}

	ws, resp, err := dialer.DialContext(ctx, u.String(), http.Header{
		"Origin": []string{"http://localhost"},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer resp.Body.Close()

	ty, _, err := ws.ReadMessage()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if ty != websocket.BinaryMessage {
		return nil, trace.BadParameter("unexpected websocket message received %d", ty)
	}

	stream := web.NewTerminalStream(ctx, ws, utils.NewLogger())
	return stream, trace.Wrap(err)
}
