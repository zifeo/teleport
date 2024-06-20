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
	"log/slog"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	authorizationpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/authorization/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
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
	userID := req.GetSubject().GetId()
	login := req.GetAction().GetLogin()
	resourceID := req.GetResource().GetId()
	switch {
	case req == nil:
		return false, trace.BadParameter("req required")
	case req.Subject == nil:
		return false, trace.BadParameter("subject required")
	case req.Action == nil:
		return false, trace.BadParameter("action required")
	case req.Resource == nil:
		return false, trace.BadParameter("resource required")
	case req.Subject.Kind == "":
		return false, trace.BadParameter("subject kind required")
	case req.Subject.Kind != types.KindUser:
		return false, trace.BadParameter("subject kind %q not supported", req.Subject.Kind)
	case userID == "":
		return false, trace.BadParameter("subject ID required")
	case req.Action.Verb == "":
		return false, trace.BadParameter("action verb required")
	case req.Action.Verb != "access":
		return false, trace.BadParameter("action verb %q not supported", req.Action.Verb)
	case login == "": // because we require verb="access" above
		return false, trace.BadParameter("action login required")
	case req.Resource.Kind == "":
		return false, trace.BadParameter("resource kind required")
	case req.Resource.Kind != types.KindNode:
		return false, trace.BadParameter("resource kind %q not supported", req.Resource.Kind)
	case resourceID == "":
		return false, trace.BadParameter("resource ID required")
	}

	// TODO(codingllama): Authorize and Explain should use the same algorithm.
	//  For now we'll authorize the "old" way.

	// Prepare the AccessChecker.
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
