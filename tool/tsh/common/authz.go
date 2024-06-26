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
	"regexp"
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
	ctx := cf.Context
	err := makeNodeAuthorizeRequests(
		cf,
		c.userHost,
		func(
			authzClient authorizationpb.AuthorizationServiceClient,
			req *authorizationpb.AuthorizeRequest,
			_ *clientpb.PaginatedResource,
			singleNodeMatch bool,
		) error {
			nodeID := req.Resource.GetId()

			// TODO(codingllama): Authorize the entire page at once with BatchAuthorize.
			_, err := authzClient.Authorize(ctx, req)

			var outcome string
			if err == nil {
				outcome = "yes"
			} else if err != nil {
				slog.DebugContext(ctx,
					"Authorization failed or denied",
					"error", err,
					"node", nodeID,
				)
				outcome = "no"
			}

			if singleNodeMatch {
				fmt.Printf("%s\n", outcome)
			} else {
				fmt.Printf("Node %s: %s\n", nodeID, outcome)
			}

			return nil
		},
	)
	return trace.Wrap(err)
}

func makeNodeAuthorizeRequests(
	cf *CLIConf,
	userHost string,
	visit func(
		authzClient authorizationpb.AuthorizationServiceClient,
		req *authorizationpb.AuthorizeRequest,
		resource *clientpb.PaginatedResource,
		singleNodeMatch bool,
	) error,
) error {
	tmp := strings.Split(userHost, "@")
	if len(tmp) != 2 || tmp[0] == "" || tmp[1] == "" {
		return trace.BadParameter("user@host spec invalid: %q", userHost)
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
					nodeID := resource.GetNode().GetName()

					req := &authorizationpb.AuthorizeRequest{
						Subject: &authorizationpb.Subject{
							SubjectState: &authorizationpb.SubjectState{
								MfaVerified:    true, // pass all checks
								DeviceVerified: true, // pass all checks
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
					}

					if err := visit(authzClient, req, resource, singleNodeMatch); err != nil {
						return trace.Wrap(err)
					}
				}

				return nil
			}),
	)
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func findNodesByHostname(
	ctx context.Context,
	authClient authclient.ClientI,
	hostname string,
	visit func(page []*clientpb.PaginatedResource, hasMorePages bool) error,
) error {
	// TODO(codingllama): Hacky hack!
	//  Users can't query nodes they don't have access to, but if you know the
	//  node ID you can see the deny rules taking place. (For now.)
	if uuidRE.MatchString(hostname) {
		node := &clientpb.PaginatedResource{
			Resource: &clientpb.PaginatedResource_Node{
				Node: &types.ServerV2{
					Kind: types.KindNode,
					Metadata: types.Metadata{
						Name: hostname,
					},
					Spec: types.ServerSpecV2{},
				},
			},
		}
		return trace.Wrap(visit([]*clientpb.PaginatedResource{node}, false /* hasMorePages */))
	}

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
func newExplainCommand(app *kingpin.Application) *explainCommand {
	explain := &explainCommand{
		ssh: &explainSSHCommand{},
	}

	root := app.Command("explain", "Explain RBAC decisions")
	explain.CmdClause = root

	ssh := root.Command("ssh", "Explain SSH RBAC decisions")
	explain.ssh.CmdClause = ssh
	ssh.Arg("user@host", "SSH user and host").Required().StringVar(&explain.ssh.userHost)

	return explain
}

type explainCommand struct {
	*kingpin.CmdClause

	ssh *explainSSHCommand
}

type explainSSHCommand struct {
	*kingpin.CmdClause

	userHost string
}

func (c *explainSSHCommand) run(cf *CLIConf) error {
	ctx := cf.Context

	first := true
	err := makeNodeAuthorizeRequests(
		cf,
		c.userHost,
		func(
			authzClient authorizationpb.AuthorizationServiceClient,
			req *authorizationpb.AuthorizeRequest,
			_ *clientpb.PaginatedResource,
			_ bool,
		) error {
			resp, err := authzClient.Explain(ctx, &authorizationpb.ExplainRequest{
				AuthorizeRequest: req,
			})
			if err != nil {
				return trace.Wrap(err)
			}

			if first {
				first = false
			} else {
				fmt.Println()
			}

			fmt.Printf("Explain access to node %v\n", req.Resource.GetId())
			fmt.Printf("Outcome: %v\n", resp.Outcome)
			if len(resp.Reasons) > 0 {
				fmt.Printf("Reasons: %v\n", resp.Reasons)
			}
			fmt.Printf("Effective grant: %v\n", grantToString(resp.EffectiveGrant))
			fmt.Print("All grants: ")
			for _, grant := range resp.AllGrants {
				fmt.Printf("\t%v\n", grantToString(grant))
			}

			return nil
		},
	)
	return trace.Wrap(err)
}

func grantToString(g *authorizationpb.Grant) string {
	if g == nil {
		return "nil"
	}

	var buf strings.Builder
	buf.WriteRune('(')
	// Subject (kind/id)
	if kind := g.Subject.GetKind(); kind != "" {
		buf.WriteString(kind)
		buf.WriteRune('/')
	}
	buf.WriteString(g.Subject.GetId())
	// Action
	buf.WriteString(", ")
	buf.WriteString(g.Action.GetVerb())
	// Resource (kind/id)
	buf.WriteString(", ")
	if kind := g.Resource.GetKind(); kind != "" {
		buf.WriteString(kind)
		buf.WriteRune('/')
	}
	buf.WriteString(g.Resource.GetId())
	// Nature
	buf.WriteString(", ")
	switch g.Nature {
	case authorizationpb.GrantNature_GRANT_NATURE_UNSPECIFIED:
		buf.WriteString("nature=UNSPECIFIED")
	case authorizationpb.GrantNature_GRANT_NATURE_ALLOW:
		buf.WriteString("ALLOW")
	case authorizationpb.GrantNature_GRANT_NATURE_DENY:
		buf.WriteString("DENY")
	default:
		buf.WriteString("nature=")
		buf.WriteString(g.Nature.String())
	}
	// Login
	if g.Action.GetLogin() != "" {
		buf.WriteString(", ")
		buf.WriteString("login=")
		buf.WriteString(g.Action.Login)
	}
	// GrantedBy.
	if g.GrantedBy != nil {
		buf.WriteString(", ")
		buf.WriteString("grantedBy=")
		if kind := g.GrantedBy.Kind; kind != "" {
			buf.WriteString(g.GrantedBy.Kind)
			buf.WriteRune('/')
		}
		buf.WriteString(g.GrantedBy.Id)
	}
	buf.WriteRune(')')

	return buf.String()
}
