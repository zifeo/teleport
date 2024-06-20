// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package common

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/gravitational/trace"

	clientpb "github.com/gravitational/teleport/api/client/proto"
	authorizationpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/authorization/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/client"
)

func newCanICommand(app *kingpin.Application) *canICommand {
	canI := &canICommand{
		ssh: &canISSHCommand{},
	}

	root := app.Command("can-i", "Verify current user permissions")
	canI.CmdClause = root

	ssh := root.Command("ssh", "Verify SSH permissions")
	canI.ssh.CmdClause = ssh
	ssh.Arg("user@host", "SSH user and host").Required().StringVar(&canI.ssh.userHost)

	return canI
}

type canICommand struct {
	*kingpin.CmdClause

	ssh *canISSHCommand
}

type canISSHCommand struct {
	*kingpin.CmdClause

	userHost string
}

func (c *canISSHCommand) run(cf *CLIConf) error {
	tmp := strings.Split(c.userHost, "@")
	if len(tmp) != 2 || tmp[0] == "" || tmp[1] == "" {
		return trace.BadParameter("user@host spec invalid: %q", c.userHost)
	}
	user := tmp[0]
	host := tmp[1]

	teleportClient, err := makeClient(cf)
	if err != nil {
		return trace.Wrap(err)
	}

	ctx := cf.Context
	var clusterClient *client.ClusterClient
	var authClient authclient.ClientI
	var authzClient authorizationpb.AuthorizationServiceClient
	if err := client.RetryWithRelogin(ctx, teleportClient, func() error {
		var err error
		clusterClient, err = teleportClient.ConnectToCluster(ctx)
		if err != nil {
			return trace.Wrap(err)
		}

		// TODO(codingllama): Allow asking a custom cluster?
		authClient, err = clusterClient.ConnectToRootCluster(ctx)
		if err != nil {
			clusterClient.Close()
			return trace.Wrap(err)
		}

		authzClient = authClient.AuthorizationClient()

		// Run the main logic outside of the retry loop.
		return nil
	}); err != nil {
		return trace.Wrap(err)
	}
	defer clusterClient.Close()
	defer authClient.Close()

	isAuthorized := func(nodeID string) bool {
		_, err := authzClient.Authorize(ctx, &authorizationpb.AuthorizeRequest{
			Subject: &authorizationpb.Subject{
				SubjectState: &authorizationpb.SubjectState{
					MfaVerified:    true, // clear all checks
					DeviceVerified: true, // clear all checks
				},
			},
			Action: &authorizationpb.Action{
				Verb:  "access",
				Login: user,
			},
			Resource: &authorizationpb.Resource{
				Kind: types.KindNode,
				Id:   nodeID,
			},
			// Override non-state Subject fields with current the identity.
			UseCallerAsSubject: true,
		})
		if err == nil {
			return true
		}

		slog.DebugContext(ctx,
			"Authorization failed or denied",
			"error", err,
			"node", nodeID,
		)
		return false
	}

	firstPage := true
	return trace.Wrap(
		findNodesByHostname(
			ctx,
			authClient,
			host,
			func(page []*clientpb.PaginatedResource, hasMorePages bool) error {
				// If it's a single node we don't print the node ID.
				// Save this info for future invocations.
				singleNodeMatch := firstPage && len(page) == 1 && !hasMorePages
				firstPage = false

				for _, resource := range page {
					name := resource.GetNode().GetName()

					// TODO(codingllama): Authorize the entire page at once with BatchAuthorize.
					var outcome string
					if isAuthorized(name) {
						outcome = "yes"
					} else {
						outcome = "no"
					}

					if singleNodeMatch {
						fmt.Printf("%s\n", outcome)
					} else {
						fmt.Printf("Node %s: %s\n", name, outcome)
					}
				}

				return nil
			}),
	)
}

func findNodesByHostname(
	ctx context.Context,
	authClient authclient.ClientI,
	hostname string,
	visit func(page []*clientpb.PaginatedResource, hasMorePages bool) error,
) error {
	var pageToken string
	for {
		resourcesResp, err := authClient.ListUnifiedResources(ctx, &clientpb.ListUnifiedResourcesRequest{
			Kinds:               []string{types.KindNode},
			Limit:               100, // arbitrary
			StartKey:            pageToken,
			PredicateExpression: fmt.Sprintf("resource.spec.hostname == %q", hostname),
			SortBy: types.SortBy{
				Field: types.ResourceMetadataName,
			},
		})
		if err != nil {
			return trace.Wrap(err)
		}
		slog.DebugContext(ctx,
			"ListUnifiedResources response",
			"hostname", host,
			"matching_nodes", len(resourcesResp.Resources),
		)

		// Do we have any results?
		if len(resourcesResp.Resources) == 0 && pageToken == "" {
			return trace.NotFound("no nodes found for hostname %q", hostname)
		}

		if err := visit(resourcesResp.Resources, resourcesResp.NextKey != "" /* hasMorePages */); err != nil {
			return trace.Wrap(err)
		}

		pageToken = resourcesResp.NextKey
		if pageToken == "" {
			break
		}
	}
	return nil
}
