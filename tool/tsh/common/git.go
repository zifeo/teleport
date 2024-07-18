/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
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

package common

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"

	apiclient "github.com/gravitational/teleport/api/client"
	tracessh "github.com/gravitational/teleport/api/observability/tracing/ssh"
	"github.com/gravitational/teleport/api/utils/prompt"
	alpncommon "github.com/gravitational/teleport/lib/srv/alpnproxy/common"
)

func onGitClone(cf *CLIConf) error {
	tc, err := makeClient(cf)
	if err != nil {
		return trace.Wrap(err)
	}

	app, err := getRegisteredApp(cf, tc)
	if err != nil {
		return trace.Wrap(err)
	}

	if !app.IsGitHub() {
		return trace.BadParameter("app %v of type %v is not supported for %v", app.GetName(), app.GetProtocol(), cf.command)
	}

	org, repo, ok := parseGitURL(cf.GitURL)
	if !ok {
		return trace.BadParameter("bad git URL %s", cf.GitURL)
	}

	if app.GetGitHubOrganization() != org {
		return trace.BadParameter("app %s is intended for organziation %s but got %s", app.GetName(), app.GetGitHubOrganization(), org)
	}

	cf.GitSaveSSHConfig = true
	if err := onGitSSHConfig(cf); err != nil {
		return trace.Wrap(err)
	}

	slog.DebugContext(cf.Context, "Calling git clone.", "url", cf.GitURL, "org", org, "repo", repo)

	gitSSHCommand := fmt.Sprintf("%s git ssh --app %s --username %s", cf.executablePath, cf.AppName, cf.GitHubUsername)
	cmd := exec.Command("git", "clone", cf.GitURL, "-c", "core.sshCommand="+gitSSHCommand)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.Env = append(cmd.Env, "GIT_SSH_COMMAND="+gitSSHCommand)
	return trace.Wrap(cmd.Run())
}

func parseGitURL(input string) (string, string, bool) {
	if strings.HasSuffix(input, ".git") {
		return parseGitURL(strings.TrimSuffix(input, ".git"))
	}

	switch {
	case strings.HasPrefix(input, "https://"):
		return "", "", false

	case strings.Contains(input, "@") && strings.Contains(input, ":"):
		_, orgAndRepo, ok := strings.Cut(input, ":")
		if !ok {
			return "", "", false
		}
		return parseGitURL(orgAndRepo)

	case strings.Count(input, "/") == 1:
		org, repo, ok := strings.Cut(input, "/")
		if !ok {
			return "", "", false
		}
		return org, repo, true

	default:
		return "", "", false
	}
}

func onGitSSH(cf *CLIConf) error {
	ctx := cf.Context
	slog.DebugContext(cf.Context, "onGitSSH", "app", cf.AppName, "username", cf.GitHubUsername, "options", cf.Options, "user_host", cf.UserHost, "command", cf.RemoteCommand)

	// TODO move this to prompt.Stdin?
	if !prompt.Stdin().IsTerminal() {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return trace.Wrap(err)
		}
		closeFunc = tty.Close
		defer tty.Close()

		cr := prompt.NewContextReader(tty)
		go cr.HandleInterrupt()
		prompt.SetStdin(cr)
	}
	/*
		password, err := tc.AskPassword(cf.Context)
		if err != nil {
			return trace.Wrap(err)
		}
		if password != "abcdef" {
			return trace.BadParameter("bad password")
		}
	*/

	tc, err := makeClient(cf)
	if err != nil {
		return trace.Wrap(err)
	}

	// TODO relogin, per-session MFA, verify username etc.
	appCert, needLogin, err := loadAppCertificate(tc, cf.AppName)
	if err != nil {
		return trace.Wrap(err)
	}
	if needLogin {
		return trace.AccessDenied("app session for %q is expired. Please login the app with `tsh apps login %v", cf.AppName, cf.AppName)
	}

	// TODO make this a helper?
	dialer := apiclient.NewALPNDialer(apiclient.ALPNDialerConfig{
		ALPNConnUpgradeRequired: tc.TLSRoutingConnUpgradeRequired,
		GetClusterCAs:           tc.RootClusterCACertPool,
		TLSConfig: &tls.Config{
			// TODO should we use -ping?
			NextProtos:         []string{string(alpncommon.ProtocolGitSSH)},
			InsecureSkipVerify: tc.InsecureSkipVerify,
			Certificates:       []tls.Certificate{appCert},
		},
	})
	serverConn, err := dialer.DialContext(cf.Context, "tcp", tc.WebProxyAddr)
	if err != nil {
		return trace.Wrap(err)
	}

	sshconn, chans, reqs, err := tracessh.NewClientConn(
		cf.Context,
		serverConn,
		tc.Host+":22",
		&ssh.ClientConfig{
			User:            tc.HostLogin, // Should be "git".
			HostKeyCallback: tc.HostKeyCallback,
			Auth:            nil, // No auth.
		},
	)
	if err != nil {
		return trace.Wrap(err)
	}

	// TODO
	emptyCh := make(chan *ssh.Request)
	close(emptyCh)
	client := tracessh.NewClient(sshconn, chans, emptyCh)
	go handleGlobalRequests(cf.Context, reqs)

	session, err := client.NewSession(cf.Context)
	if err != nil {
		return trace.Wrap(err)
	}

	if gitProtocol := os.Getenv("GIT_PROTOCOL"); gitProtocol != "" {
		slog.DebugContext(ctx, "=== send env", "git_protocol", gitProtocol)
		if err := session.SetEnvs(ctx, map[string]string{"GIT_PROTOCOL": gitProtocol}); err != nil {
			slog.WarnContext(ctx, "Failed to set remote server env", "error", err)
		}
	}

	// TODO catch signal
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- session.Start(ctx, strings.Join(cf.RemoteCommand, " "))
	}()
	select {
	// Run returned a result, return that back to the caller.
	case err := <-errCh:
		if err != nil {
			return trace.Wrap(err)
		}
	// The passed in context timed out. This is often due to the user hitting
	// Ctrl-C.
	case <-ctx.Done():
		return nil
	}

	go func() {
		defer stdinPipe.Close()
		io.Copy(stdinPipe, os.Stdin)
		slog.DebugContext(ctx, "=== stdin done")
	}()
	go func() {
		io.Copy(os.Stdout, stdoutPipe)
		slog.DebugContext(ctx, "=== stdout done")
	}()
	go func() {
		io.Copy(os.Stderr, stderrPipe)
		slog.DebugContext(ctx, "=== stderr done")
	}()
	return trace.Wrap(session.Wait())
}

func handleGlobalRequests(ctx context.Context, requestCh <-chan *ssh.Request) {
	for {
		select {
		case r := <-requestCh:
			// When the channel is closing, nil is returned.
			if r == nil {
				return
			}
			slog.DebugContext(ctx, "=== global request", "type", r.Type)
			err := r.Reply(false, nil)
			if err != nil {
				log.Warnf("Unable to reply to %v request.", r.Type)
				continue
			}
		case <-ctx.Done():
			return
		}
	}
}
