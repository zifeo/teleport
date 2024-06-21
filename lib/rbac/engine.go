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

package rbac

import (
	"context"
	"fmt"
	"log/slog"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	authorizationpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/authorization/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrAccessDenied is a redacted AccessDenied error.
	ErrAccessDenied = &trace.AccessDeniedError{Message: "access denied"}
	// ErrInternal is a redacted "internal" error, purposefully typed as
	// AccessDenied.
	ErrInternal = &trace.AccessDeniedError{Message: "internal server error"}
)

type AuthServer interface {
	GetAuthPreference(ctx context.Context) (types.AuthPreference, error)
	GetNode(ctx context.Context, namespace, name string) (types.Server, error)
	GetUser(ctx context.Context, name string, withSecrets bool) (types.User, error)
	GetUserOrLoginState(ctx context.Context, username string) (services.UserState, error)
}

type Engine struct {
	logger      *slog.Logger
	clusterName string

	// TODO(codingllama): Carefully consider caching.
	authServer AuthServer
	roleGetter services.RoleGetter

	// AccessInfo set via WithSubjectAccessInfo, otherwise nil.
	subjectAccessInfo *services.AccessInfo
}

type EngineParams struct {
	Logger      *slog.Logger
	ClusterName string
	// TODO(codingllama): Carefully consider caching.
	AuthServer AuthServer
	// TODO(codingllama): Carefully consider caching.
	RoleGetter services.RoleGetter
}

func NewEngine(params EngineParams) (*Engine, error) {
	switch {
	case params.ClusterName == "":
		return nil, trace.BadParameter("params.ClusterName required")
	case params.AuthServer == nil:
		return nil, trace.BadParameter("params.AuthServer required")
	case params.RoleGetter == nil:
		return nil, trace.BadParameter("params.RoleGetter required")
	}

	logger := params.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Engine{
		logger:      logger,
		clusterName: params.ClusterName,
		authServer:  params.AuthServer,
		roleGetter:  params.RoleGetter,
	}, nil
}

func (e *Engine) WithSubjectAccessInfo(accessInfo *services.AccessInfo) *Engine {
	// TODO(codingllama): Remove once roles are not encoded in the certificates.

	e2 := *e // shallow copy is fine
	e2.subjectAccessInfo = accessInfo
	return &e2
}

func (e *Engine) resolveSubjectAccessInfo(ctx context.Context, userID string) (*services.AccessInfo, error) {
	// Prefer AccessInfo supplied by WithSubjectAccessInfo.
	// UserID should match, but we sanity check it just in case.
	if e.subjectAccessInfo != nil && e.subjectAccessInfo.Username == userID {
		return e.subjectAccessInfo, nil
	}

	userState, err := e.authServer.GetUserOrLoginState(ctx, userID)
	if err != nil {
		e.logger.DebugContext(ctx, "resolveSubjectAccessInfo: GetUserOrLoginState failed", "error", err)
		// err swallowed on purpose, assumed to be NotFound.
		return nil, trace.Wrap(ErrAccessDenied)
	}
	return services.AccessInfoFromUserState(userState), nil
}

func (e *Engine) Authorize(ctx context.Context, req *authorizationpb.AuthorizeRequest) (ok bool, err error) {
	if err := validateAuthorizeRequest(req); err != nil {
		return false, trace.Wrap(err)
	}

	// TODO(codingllama): Authorize and Explain should use the same algorithm.
	//  For now we'll authorize the "old" way.

	// Prepare the AccessChecker.
	userID := req.GetSubject().GetId()
	accessInfo, err := e.resolveSubjectAccessInfo(ctx, userID)
	if err != nil {
		// err from resolveSubjectAccessInfo already redacted.
		return false, trace.Wrap(err)
	}
	accessChecker, err := services.NewAccessChecker(accessInfo, e.clusterName, e.roleGetter)
	if err != nil {
		e.logger.WarnContext(ctx, "Authorize: failed to create AccessChecker", "error", err)
		// err swallowed on purpose.
		return false, trace.Wrap(ErrInternal)
	}

	// Fetch resource.
	resourceID := req.GetResource().GetId()
	node, err := e.authServer.GetNode(ctx, apidefaults.Namespace, resourceID)
	if err != nil {
		e.logger.DebugContext(ctx, "Authorize: failed to read node", "error", err, "name", resourceID)
		// err swallowed on purpose, assumed to be NotFound.
		return false, trace.Wrap(ErrAccessDenied)
	}

	// Determine AccessState.
	authPreference, err := e.authServer.GetAuthPreference(ctx)
	if err != nil {
		e.logger.WarnContext(ctx, "Authorize: failed to read AuthPreference", "error", err)
		// err swallowed on purpose.
		return false, trace.Wrap(ErrInternal)
	}
	accessState := accessChecker.GetAccessState(authPreference)
	// Let request override the access state.
	if state := req.Subject.SubjectState; state != nil {
		accessState.MFAVerified = state.MfaVerified
		accessState.DeviceVerified = state.DeviceVerified
	}

	// Determine access.
	login := req.GetAction().GetLogin()
	accessErr := accessChecker.CheckAccess(
		node,
		accessState,
		services.NewLoginMatcher(login),
	)
	ok = accessErr == nil
	if !ok {
		e.logger.DebugContext(ctx,
			"Authorize: authorization check failed",
			"error", err,
			"req", req,
		)
	}

	return ok, nil
}

func validateAuthorizeRequest(req *authorizationpb.AuthorizeRequest) error {
	switch {
	case req == nil:
		return trace.BadParameter("authorize_request required")
	case req.Subject == nil:
		return trace.BadParameter("subject required")
	case req.Action == nil:
		return trace.BadParameter("action required")
	case req.Resource == nil:
		return trace.BadParameter("resource required")
	case req.Subject.Kind == "":
		return trace.BadParameter("subject kind required")
	case req.Subject.Kind != types.KindUser:
		return trace.BadParameter("subject kind %q not supported", req.Subject.Kind)
	case req.Subject.Id == "":
		return trace.BadParameter("subject ID required")
	case req.Action.Verb == "":
		return trace.BadParameter("action verb required")
	case req.Action.Verb != "access":
		return trace.BadParameter("action verb %q not supported", req.Action.Verb)
	case req.Action.Login == "": // because we require verb="access" above
		return trace.BadParameter("action login required")
	case req.Resource.Kind == "":
		return trace.BadParameter("resource kind required")
	case req.Resource.Kind != types.KindNode:
		return trace.BadParameter("resource kind %q not supported", req.Resource.Kind)
	case req.Resource.Id == "":
		return trace.BadParameter("resource ID required")
	default:
		return nil
	}
}

func (e *Engine) Explain(ctx context.Context, req *authorizationpb.ExplainRequest) (*authorizationpb.ExplainResponse, error) {
	if err := validateAuthorizeRequest(req.AuthorizeRequest); err != nil {
		return nil, trace.Wrap(err)
	}

	expandedBundle, err := e.fetchBundle(ctx, req.AuthorizeRequest)
	if err != nil {
		// err from fetchBundle already redacted.
		return nil, trace.Wrap(err)
	}

	var effectiveGrant *authorizationpb.Grant
	var allGrants []*authorizationpb.Grant
	if err := expandGrants(req.AuthorizeRequest.Action, expandedBundle, func(grant authorizationpb.Grant) (cont bool) {
		g := &grant

		if effectiveGrant == nil {
			effectiveGrant = g
		} else if effectiveGrant.Nature == authorizationpb.GrantNature_GRANT_NATURE_ALLOW &&
			g.Nature == authorizationpb.GrantNature_GRANT_NATURE_DENY {
			effectiveGrant = g // Deny takes precedence
		}

		allGrants = append(allGrants, g)
		return true
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	// If no grants exist the implied deny-all grant wins.
	if len(allGrants) == 0 {
		denyAll := &authorizationpb.Grant{
			Subject: &authorizationpb.Subject{
				Id: "*",
			},
			Action: &authorizationpb.Action{
				Verb: "*",
			},
			Resource: &authorizationpb.Resource{
				Id: "*",
			},
			Nature: authorizationpb.GrantNature_GRANT_NATURE_DENY,
		}
		effectiveGrant = denyAll
		allGrants = append(allGrants, denyAll)
	}

	var outcome authorizationpb.AuthorizeOutcome
	if effectiveGrant.Nature == authorizationpb.GrantNature_GRANT_NATURE_ALLOW {
		outcome = authorizationpb.AuthorizeOutcome_AUTHORIZE_OUTCOME_ALLOWED
	} else {
		outcome = authorizationpb.AuthorizeOutcome_AUTHORIZE_OUTCOME_DENIED
	}

	return &authorizationpb.ExplainResponse{
		Outcome: outcome,
		// TODO(codingllama): Deny reasons.
		// Reasons: nil,
		EffectiveGrant: effectiveGrant,
		AllGrants:      allGrants,
	}, nil
}

type expandedBundle struct {
	*authorizationpb.AuthorizationBundle

	subjects []*Subject

	// Parallel to AuthorizationBundle.Resources.
	resources []*Resource
}

func (e *expandedBundle) subjectAssignedRole(_ *Subject, _ *Resource, _ *authorizationpb.Role) bool {
	// TODO(codingllama): Support multi-user bundles
	//  (like we would have for Enumerate or EnumerateChange).

	// Always true for single-user expanded bundles.
	return true
}

func (e *Engine) fetchBundle(
	ctx context.Context,
	req *authorizationpb.AuthorizeRequest,
) (*expandedBundle, error) {
	// AccessInfo.
	accessInfo, err := e.resolveSubjectAccessInfo(ctx, req.Subject.Id)
	if err != nil {
		// err from resolveSubjectAccessInfo already redacted.
		return nil, trace.Wrap(err)
	}
	subject := &Subject{
		Subject: proto.Clone(req.Subject).(*authorizationpb.Subject),
	}
	// Copy traits from AccessInfo.
	subject.Subject.Traits = &authorizationpb.Traits{}
	for key, vals := range accessInfo.Traits {
		subject.Subject.Traits.Traits = append(subject.Subject.Traits.Traits, &authorizationpb.Trait{
			Key:    key,
			Values: vals,
		})
	}

	// Roles.
	roleSet, err := services.FetchRoles(accessInfo.Roles, e.roleGetter, accessInfo.Traits)
	if err != nil {
		e.logger.WarnContext(ctx, "Explain: failed to fetch Subject roles", "error", err)
		return nil, trace.Wrap(ErrInternal)
	}
	roles := make([]*authorizationpb.Role, len(roleSet))
	for i, role := range roleSet {
		roleV6, ok := role.(*types.RoleV6)
		if !ok {
			e.logger.WarnContext(ctx,
				"Explain: failed to cast role to RoleV6",
				"error", err,
				"role_type", fmt.Sprintf("%T", role),
			)
			return nil, trace.Wrap(ErrInternal)
		}

		roles[i] = &authorizationpb.Role{
			Resource: roleV6,
		}
	}

	// Node.
	node, err := e.authServer.GetNode(ctx, apidefaults.Namespace, req.Resource.Id)
	if err != nil {
		e.logger.DebugContext(ctx, "Authorize: failed to read node", "error", err, "name", req.Resource.Id)
		// err swallowed on purpose, assumed to be NotFound.
		return nil, trace.Wrap(ErrAccessDenied)
	}
	resource := &Resource{
		Resource:  proto.Clone(req.Resource).(*authorizationpb.Resource),
		checkable: node,
	}
	// TODO(codingllama): Combine labels with ServerInfo.
	resource.Labels = mapToLabels(node.GetLabels())

	// TODO(codingllama): ServerInfos.
	// TODO(codingllama): AccessRequests.
	// TODO(codingllama): AccessLists.

	return &expandedBundle{
		AuthorizationBundle: &authorizationpb.AuthorizationBundle{
			// Users: nil,
			Roles:     roles,
			Resources: []*authorizationpb.Resource{resource.Resource},
			// ServerInfos:    nil,
			// AccessRequests: nil,
			// AccessLists:    nil,
		},
		subjects:  []*Subject{subject},
		resources: []*Resource{resource},
	}, nil
}

func expandGrants(
	action *authorizationpb.Action,
	bundle *expandedBundle,
	visit func(grant authorizationpb.Grant) (cont bool),
) error {
	for _, s := range bundle.subjects {
		for _, role := range bundle.Roles {
			source := &authorizationpb.GrantSource{
				Kind: role.GetResource().Kind,
				Id:   role.GetResource().GetName(),
			}
			for _, resource := range bundle.resources {
				if !bundle.subjectAssignedRole(s, resource, role) {
					continue
				}
				switch cont, err := expandGrant(
					s, action, resource, role.GetResource(), source, visit); {
				case err != nil:
					return trace.Wrap(err)
				case !cont:
					return nil
				}
			}
		}
	}
	return nil
}

func expandGrant(
	subject *Subject,
	action *authorizationpb.Action,
	resource *Resource,
	role *types.RoleV6,
	source *authorizationpb.GrantSource,
	visit func(grant authorizationpb.Grant) (cont bool),
) (cont bool, err error) {
	// TODO(codingllama): SSH assumption.
	var matchers services.RoleMatchers
	if action.Login != "" {
		matchers = append(matchers, services.NewLoginMatcher(action.Login))
	}

	// Expand deny grant.
	ok, err := roleDenies(
		role,
		resource.AccessCheckable(),
		matchers,
		subject.GetTraits(),
		false, /* debug */
	)
	if err != nil {
		return false, trace.Wrap(err)
	}
	if ok {
		// Allocations avoided on purpose.
		if cont := visit(authorizationpb.Grant{
			Subject:   subject.Subject,
			Action:    action,
			Resource:  resource.Resource,
			Nature:    authorizationpb.GrantNature_GRANT_NATURE_DENY,
			GrantedBy: source,
		}); !cont {
			return cont, nil
		}
	}

	// Expand allow grant.
	ok, err = roleAllows(
		role,
		resource.AccessCheckable(),
		matchers,
		subject.GetTraits(),
		false, /* debug */
	)
	if err != nil {
		return false, trace.Wrap(err)
	}
	if ok {
		// Allocations avoided on purpose.
		if cont := visit(authorizationpb.Grant{
			Subject:   subject.Subject,
			Action:    action,
			Resource:  resource.Resource,
			Nature:    authorizationpb.GrantNature_GRANT_NATURE_ALLOW,
			GrantedBy: source,
		}); !cont {
			return cont, nil
		}
	}

	return true, nil
}

type roleMatchFunc func(*types.RoleV6, services.AccessCheckable, services.RoleMatchers, wrappers.Traits, bool) (bool, error)

func roleAllows(
	role *types.RoleV6,
	resource services.AccessCheckable,
	matchers services.RoleMatchers,
	traits wrappers.Traits,
	debug bool,
) (bool, error) {
	return roleMatches(types.Allow, role, resource, matchers, traits, debug)
}

func roleDenies(
	role *types.RoleV6,
	resource services.AccessCheckable,
	matchers services.RoleMatchers,
	traits wrappers.Traits,
	debug bool,
) (bool, error) {
	return roleMatches(types.Deny, role, resource, matchers, traits, debug)
}

func roleMatches(
	cond types.RoleConditionType,
	role *types.RoleV6,
	resource services.AccessCheckable,
	matchers services.RoleMatchers,
	traits wrappers.Traits,
	debug bool,
) (bool, error) {
	// Ideally we want to rewrite AccessChecker so it uses rbac.Engine, not the
	// other way around.

	match, _, err := services.CheckRoleLabelsMatch(cond, role, traits, resource, debug)
	if err != nil {
		return false, trace.Wrap(err)
	}
	if !match {
		return false, nil
	}
	if cond == types.Deny {
		// Denies are eager.
		return true, nil
	}

	if cond == types.Allow {
		match, err = matchers.MatchAll(role, cond)
	} else {
		// TODO(codingllama): Capture/log matcher somehow?
		match, _, err = matchers.MatchAny(role, cond)
	}
	if err != nil {
		return false, trace.Wrap(err)
	}

	// TODO(codingllama): Verify MFA and trusted device?

	return match, nil
}

func mapToLabels(m map[string]string) *authorizationpb.Labels {
	labels := &authorizationpb.Labels{
		Labels: make([]*authorizationpb.Label, 0, len(m)),
	}
	for key, value := range m {
		labels.Labels = append(labels.Labels, &authorizationpb.Label{
			Key:    key,
			Values: []string{value},
		})
	}
	return labels
}
