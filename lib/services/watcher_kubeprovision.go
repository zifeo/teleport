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

package services

import (
	"context"
	kubeprovisionv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/kubeprovision/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"sync"
)

// KubeProvisionWatcherConfig is an KubeProvisionWatcher configuration.
type KubeProvisionWatcherConfig struct {
	// ResourceWatcherConfig is the resource watcher configuration.
	ResourceWatcherConfig
	// KubernetesGetter is responsible for fetching kube_cluster resources.
	KubeProvisionsGetter
	// KubeClustersC receives up-to-date list of all kube_cluster resources.
	KubeProvisionC chan []*kubeprovisionv1.KubeProvision
}

// kubeProvisionCollector accompanies resourceWatcher when monitoring kube_provision resources.
type kubeProvisionCollector struct {
	// KubeClusterWatcherConfig is the watcher configuration.
	KubeProvisionWatcherConfig
	// current holds a map of the currently known kube_cluster resources.
	current map[string]*kubeprovisionv1.KubeProvision
	// lock protects the "current" map.
	lock sync.RWMutex
	// initializationC is used to check whether the initial sync has completed
	initializationC chan struct{}
	once            sync.Once
}

// KubeProvisionWatcher is built on top of resourceWatcher to monitor kube_provision resources.
type KubeProvisionWatcher struct {
	*resourceWatcher
	*kubeProvisionCollector
}

// NewKubeProvisionWatcher returns a new instance of KubeProvisionWatcher.
func NewKubeProvisionWatcher(ctx context.Context, cfg KubeProvisionWatcherConfig) (*KubeProvisionWatcher, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	collector := &kubeProvisionCollector{
		KubeProvisionWatcherConfig: cfg,
		initializationC:            make(chan struct{}),
	}
	watcher, err := newResourceWatcher(ctx, collector, cfg.ResourceWatcherConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &KubeProvisionWatcher{watcher, collector}, nil
}

// CheckAndSetDefaults checks parameters and sets default values.
func (cfg *KubeProvisionWatcherConfig) CheckAndSetDefaults() error {
	if err := cfg.ResourceWatcherConfig.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if cfg.KubeProvisionsGetter == nil {
		getter, ok := cfg.Client.(KubeProvisionsGetter)
		if !ok {
			return trace.BadParameter("missing parameter KubeProvisionsGetter and Client not usable as KubeProvisionsGetter")
		}
		cfg.KubeProvisionsGetter = getter
	}
	if cfg.KubeProvisionC == nil {
		cfg.KubeProvisionC = make(chan []*kubeprovisionv1.KubeProvision)
	}
	return nil
}

// isInitialized is used to check that the cache has done its initial
// sync
func (k *kubeProvisionCollector) initializationChan() <-chan struct{} {
	return k.initializationC
}

// resourceKinds specifies the resource kind to watch.
func (k *kubeProvisionCollector) resourceKinds() []types.WatchKind {
	return []types.WatchKind{{Kind: types.KindKubeProvision}}
}

const pageSize = 10

func listAllKubeProvisions(ctx context.Context, getter KubeProvisionsGetter) ([]*kubeprovisionv1.KubeProvision, error) {
	pageToken := ""
	allProvisions := []*kubeprovisionv1.KubeProvision{}
	for {
		pageProvisions, nextPage, err := getter.ListKubeProvisions(ctx, pageSize, pageToken)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		allProvisions = append(allProvisions, pageProvisions...)
		if nextPage == "" {
			break
		}
		pageToken = nextPage
	}

	return allProvisions, nil
}

// getResourcesAndUpdateCurrent refreshes the list of current resources.
func (k *kubeProvisionCollector) getResourcesAndUpdateCurrent(ctx context.Context) error {
	provisions, err := listAllKubeProvisions(ctx, k.KubeProvisionsGetter)
	if err != nil {
		return trace.Wrap(err)
	}
	newCurrent := make(map[string]*kubeprovisionv1.KubeProvision, len(provisions))
	for _, provision := range provisions {
		newCurrent[provision.Metadata.GetName()] = provision
	}
	k.lock.Lock()
	defer k.lock.Unlock()
	k.current = newCurrent

	select {
	case <-ctx.Done():
		return trace.Wrap(ctx.Err())
	case k.KubeProvisionC <- provisions:
	}

	k.defineCollectorAsInitialized()

	return nil
}

func (k *kubeProvisionCollector) defineCollectorAsInitialized() {
	k.once.Do(func() {
		// mark watcher as initialized.
		close(k.initializationC)
	})
}

// processEventsAndUpdateCurrent is called when a watcher event is received.
func (k *kubeProvisionCollector) processEventsAndUpdateCurrent(ctx context.Context, events []types.Event) {
	k.lock.Lock()
	defer k.lock.Unlock()

	for _, event := range events {
		if event.Resource == nil || event.Resource.GetKind() != types.KindKubeProvision {
			k.Log.Warnf("Unexpected event: %v.", event)
			continue
		}
		switch event.Type {
		case types.OpDelete:
			delete(k.current, event.Resource.GetName())
			resources := resourcesToSlice(k.current)
			select {
			case <-ctx.Done():
			case k.KubeProvisionC <- resources:
			}
		case types.OpPut:
			k.Log.Debugf("DBGG. Received event: %v.", event)
			//kubeProvision, ok := event.Resource.(kubeprovisionv1.KubeProvision)
			//if !ok {
			//	k.Log.Warnf("Unexpected resource type %T.", event.Resource)
			//	continue
			//}
			//k.current[kubeProvision.GetName()] = kubeProvision
			//resources := resourcesToSlice(k.current)

			select {
			case <-ctx.Done():
			case k.KubeProvisionC <- nil:
			}

		default:
			k.Log.Warnf("Unsupported event type %s.", event.Type)
		}
	}
}

func (*kubeProvisionCollector) notifyStale() {}
