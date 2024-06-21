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

package authorizationv1

import (
	"context"
	"log/slog"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/proto"

	authorizationpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/authorization/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/rbac"
	"github.com/gravitational/teleport/lib/services"
)

var (
	errAccessDenied = rbac.ErrAccessDenied
	errInternal     = rbac.ErrInternal
)

type AuthPreferenceGetter interface {
	GetAuthPreference(ctx context.Context) (types.AuthPreference, error)
}

type Service struct {
	authorizationpb.UnimplementedAuthorizationServiceServer

	logger               *slog.Logger
	authorizer           authz.Authorizer
	authPreferenceGetter AuthPreferenceGetter
	userGetter           services.UserGetter
	engine               *rbac.Engine
}

type ServiceParams struct {
	Logger     *slog.Logger
	Authorizer authz.Authorizer
	// AuthPreferenceGetter for cluster preferences.
	// May use a cached source.
	AuthPreferenceGetter AuthPreferenceGetter
	// UserGetter for eventual queries on the context user.
	// May use a cached source.
	UserGetter services.UserGetter
	Engine     *rbac.Engine
}

func New(params ServiceParams) (*Service, error) {
	switch {
	case params.Authorizer == nil:
		return nil, trace.BadParameter("params.Authorizer required")
	case params.AuthPreferenceGetter == nil:
		return nil, trace.BadParameter("params.AuthPreferenceGetter required")
	case params.UserGetter == nil:
		return nil, trace.BadParameter("params.Authorizer required")
	case params.Engine == nil:
		return nil, trace.BadParameter("params.Engine required")
	}

	logger := params.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Service{
		logger:               logger,
		authorizer:           params.Authorizer,
		authPreferenceGetter: params.AuthPreferenceGetter,
		userGetter:           params.UserGetter,
		engine:               params.Engine,
	}, nil
}

func (s *Service) Authorize(ctx context.Context, req *authorizationpb.AuthorizeRequest) (*authorizationpb.AuthorizeResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		// err swallowed on purpose.
		return nil, trace.Wrap(errAccessDenied)
	}
	// TODO(codingllama): Verify authorization to perform this call!

	engine := s.engine

	if req.UseCallerAsSubject {
		identityAccessInfo, err := s.assignCallerToSubject(ctx, authCtx, &req.Subject)
		if err != nil {
			// err from assignCallerToSubject is already redacted.
			return nil, trace.Wrap(err)
		}

		// Override engine's identity, we want to use the certificate as-is.
		engine = engine.WithSubjectAccessInfo(identityAccessInfo)
	}

	switch ok, err := engine.Authorize(ctx, req); {
	case err != nil:
		s.logger.DebugContext(ctx, "Authorize failed before actual RBAC check", "error", err)
		fallthrough
	case !ok:
		// Authorize error is already redacted.
		return nil, trace.Wrap(err)
	default:
		return &authorizationpb.AuthorizeResponse{}, nil
	}
}

func (s *Service) Explain(ctx context.Context, req *authorizationpb.ExplainRequest) (*authorizationpb.ExplainResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		// err swallowed on purpose.
		return nil, trace.Wrap(errAccessDenied)
	}
	// TODO(codingllama): Verify authorization to perform this call!

	engine := s.engine

	if req.AuthorizeRequest.GetUseCallerAsSubject() {
		identityAccessInfo, err := s.assignCallerToSubject(ctx, authCtx, &req.AuthorizeRequest.Subject)
		if err != nil {
			// err from assignCallerToSubject is already redacted.
			return nil, trace.Wrap(err)
		}

		// Override engine's identity, we want to use the certificate as-is.
		engine = engine.WithSubjectAccessInfo(identityAccessInfo)
	}

	resp, err := engine.Explain(ctx, req)
	return resp, trace.Wrap(err)
}

func (s *Service) assignCallerToSubject(ctx context.Context, authCtx *authz.Context, out **authorizationpb.Subject) (*services.AccessInfo, error) {
	kind := authCtx.User.GetKind()
	if kind != types.KindUser {
		// Let this error go non-redacted, it's an informative programming error.
		return nil, trace.BadParameter("only kind %q may set AuthorizeRequest.use_caller_as_subject", kind)
	}

	// Initialize Subject.
	var subjectBefore *authorizationpb.Subject
	if *out == nil {
		*out = &authorizationpb.Subject{}
	} else {
		subjectBefore = proto.Clone(*out).(*authorizationpb.Subject)
	}

	// Copy Subject.Kind and ID from identity.
	subject := *out
	subject.Kind = kind
	subject.Id = authCtx.User.GetName()

	// Copy SubjectState from identity.
	if subject.SubjectState == nil {
		authPreference, err := s.authPreferenceGetter.GetAuthPreference(ctx)
		if err != nil {
			s.logger.WarnContext(ctx, "assignCallerToSubject: failed to read AuthPreferences", "error", err)
			return nil, trace.Wrap(errInternal)
		}
		accessState := authCtx.GetAccessState(authPreference)
		subject.SubjectState = &authorizationpb.SubjectState{
			MfaVerified:    accessState.MFAVerified,
			DeviceVerified: accessState.DeviceVerified,
		}
	}

	// Prepare AccessInfo from Identity.
	identity := authCtx.Identity.GetIdentity()
	identityAccessInfo, err := services.AccessInfoFromLocalIdentity(identity, s.userGetter)
	if err != nil {
		s.logger.WarnContext(ctx, "assignCallerToSubject: failed to create AccessInfo from local identity", "error", err)
		return nil, trace.Wrap(errInternal)
	}

	s.logger.DebugContext(ctx,
		"Assigned Subject from caller",
		"subject_before", subjectBefore,
		"subject_after", subject,
	)
	return identityAccessInfo, nil
}
