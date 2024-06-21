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
	apidefaults "github.com/gravitational/teleport/api/defaults"
	authorizationpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/authorization/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/services"
)

type Subject struct {
	*authorizationpb.Subject

	traitsWrappers wrappers.Traits
}

func (s *Subject) GetTraits() wrappers.Traits {
	// Lazy initialize traitsWrappers.
	if s.traitsWrappers == nil {
		s.traitsWrappers = make(wrappers.Traits)
		for _, trait := range s.Subject.GetTraits().GetTraits() {
			key := trait.GetKey()
			if key == "" {
				continue
			}
			s.traitsWrappers[key] = trait.GetValues()
		}
	}
	return s.traitsWrappers
}

type Resource struct {
	*authorizationpb.Resource

	checkable services.AccessCheckable
}

func (r *Resource) AccessCheckable() services.AccessCheckable {
	if r.checkable == nil {
		// TODO(codingllama): Is this fallback necessary?
		r.checkable = &resourceAccessCheckableAdapter{impl: r.Resource}
	}
	return r.checkable
}

type resourceAccessCheckableAdapter struct {
	impl *authorizationpb.Resource

	allLabels map[string]string
}

func (r *resourceAccessCheckableAdapter) GetAllLabels() map[string]string {
	// Lazily initialize allLabels.
	if r.allLabels == nil {
		r.allLabels = make(map[string]string)
		for _, l := range r.impl.GetLabels().GetLabels() {
			key := l.GetKey()
			if key == "" {
				continue // Skip nil/empty.
			}
			// TODO(codingllama): Verify how labels are "reduced" in other places?
			if vals := l.GetValues(); len(vals) > 0 {
				r.allLabels[key] = vals[0]
			}
		}
	}
	return r.allLabels
}

func (r *resourceAccessCheckableAdapter) GetKind() string {
	return r.impl.GetKind()
}

func (r *resourceAccessCheckableAdapter) GetLabel(key string) (value string, ok bool) {
	m := r.GetAllLabels() // Be consistent with GetAllLabels.
	val, ok := m[key]
	return val, ok
}

func (r *resourceAccessCheckableAdapter) GetMetadata() types.Metadata {
	return types.Metadata{
		Name:      r.impl.GetId(),
		Namespace: apidefaults.Namespace,
		// Description: "",
		Labels: r.GetAllLabels(),
		// Expires: nil,
		// Revision: "",
	}
}

func (r *resourceAccessCheckableAdapter) GetName() string {
	return r.impl.GetId()
}
