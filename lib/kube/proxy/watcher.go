/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

package proxy

import (
	"context"
	"fmt"
	kubeprovisionv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/kubeprovision/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/exp/maps"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// startReconciler starts reconciler that registers/unregisters proxied
// kubernetes clusters according to the up-to-date list of kube_cluster resources.
func (s *TLSServer) startReconciler(ctx context.Context) (err error) {
	if len(s.ResourceMatchers) == 0 || s.KubeServiceType != KubeService {
		s.log.Debug("Not initializing Kube Cluster resource watcher.")
		return nil
	}
	s.reconciler, err = services.NewReconciler(services.ReconcilerConfig[types.KubeCluster]{
		Matcher:             s.matcher,
		GetCurrentResources: s.getResources,
		GetNewResources:     s.monitoredKubeClusters.get,
		OnCreate:            s.onCreate,
		OnUpdate:            s.onUpdate,
		OnDelete:            s.onDelete,
		Log:                 s.log,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	go func() {
		// reconcileTicker is used to force reconciliation when the watcher was
		// previously informed that a `kube_cluster` resource exists/changed but the
		// creation/update operation failed - e.g. login to AKS/EKS clusters can
		// fail due to missing permissions.
		// Once this happens, the state of the resource watcher won't change until
		// a new update operation is triggered (which can take a lot of time).
		// This results in the service not being able to enroll the failing cluster,
		// even if the original issue was already fixed because we won't run reconciliation again.
		// We force the reconciliation to make sure we don't drift from watcher state if
		// the issue was fixed.
		reconcileTicker := time.NewTicker(2 * time.Minute)
		defer reconcileTicker.Stop()
		for {
			select {
			case <-reconcileTicker.C:
				if err := s.reconciler.Reconcile(ctx); err != nil {
					s.log.WithError(err).Error("Failed to reconcile.")
				}
			case <-s.reconcileCh:
				if err := s.reconciler.Reconcile(ctx); err != nil {
					s.log.WithError(err).Error("Failed to reconcile.")
				} else if s.OnReconcile != nil {
					s.OnReconcile(s.fwd.kubeClusters())
				}
			case <-ctx.Done():
				s.log.Debug("Reconciler done.")
				return
			}
		}
	}()
	return nil
}

func (s *TLSServer) startKubeProvisionsReconciler(ctx context.Context) {
	s.log.Debug("Starting Kube Provisions Reconciler.")
	go func() {
		reconcileTicker := time.NewTicker(5 * time.Minute)
		defer reconcileTicker.Stop()

		for {
			select {
			case <-reconcileTicker.C:
				s.reconcileKubeProvisionsCh <- struct{}{}
			case <-ctx.Done():
				s.log.Debug("KubeProvisions reconciler ticker finished.")
				return
			}
		}

	}()

	go func() {
		for {
			select {
			case <-s.reconcileKubeProvisionsCh:
				err := s.reconcileKubeProvisions(ctx)
				if err != nil {
					s.log.WithError(err).Error("Failed to reconcile KubeProvisions.")
				}
			case <-ctx.Done():
				s.log.Debug("KubeProvisions reconciliation processing finished.")
				return
			}
		}
	}()
}

func kubeProvisionToKubeResources() {

}

func kubeProvisionToKubeClusterRoles(kp *kubeprovisionv1.KubeProvision) ([]rbacv1.ClusterRole, error) {
	kubeClusterRoles := []rbacv1.ClusterRole{}
	for _, cr := range kp.Spec.ClusterRoles {
		newClusterRole := rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   cr.Metadata.Name,
				Labels: cr.Metadata.Labels,
			},
		}

		for _, rule := range cr.Rules {
			newClusterRole.Rules = append(newClusterRole.Rules,
				rbacv1.PolicyRule{
					APIGroups: []string{""},
					Resources: rule.Resources,
					Verbs:     rule.Verbs,
				},
			)
		}
		kubeClusterRoles = append(kubeClusterRoles, newClusterRole)
	}

	return kubeClusterRoles, nil
}

func teleportRoleToKubeClusterRole(role types.RoleV6) rbacv1.ClusterRole {
	kubeClusterRole := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: role.GetName(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "pods/exec"},
				Verbs:     []string{"get", "create", "list", "watch"},
			},
		},
	}

	for _, r := range role.Spec.Allow.KubernetesResources {
		kubeClusterRole.Rules = append(kubeClusterRole.Rules,
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{r.Kind},
				Verbs:     r.Verbs,
			})
	}
	return kubeClusterRole
}

func (s *TLSServer) reconcileKubeProvisions(ctx context.Context) error {
	s.log.Debug("Reconciling KubeProvisions.")
	now := time.Now()
	defer func() {
		s.log.Debugf("KubeProvisions reconciliation process finished. Time took: %s.", time.Since(now))
	}()

	kubeProvisions, err := s.getAllKubeProvisions()
	if err != nil {
		return trace.Wrap(err)
	}
	_ = kubeProvisions

	teleportRoles, err := s.AccessPoint.GetRoles(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	_ = teleportRoles

	for _, cluster := range s.fwd.kubeClusters() {
		clusterName := cluster.GetName()

		s.fwd.rwMutexDetails.Lock()
		details := s.fwd.clusterDetails[clusterName]
		s.fwd.rwMutexDetails.Unlock()

		//kubeClient := details.kubeCreds.getKubeClient()

		config := details.kubeCreds.getKubeRestConfig()
		config.Impersonate.Groups = []string{"system:masters"}
		config.Impersonate.UserName = "teleport"

		kubeClient, err := kubernetes.NewForConfig(config)
		if err != nil {
			return trace.Wrap(err)
		}

		clusterRoles, err := kubeClient.RbacV1().ClusterRoles().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return trace.Wrap(err)
		}

		roles, err := kubeClient.RbacV1().Roles("").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return trace.Wrap(err)
		}

		clusterRoleBindings, err := kubeClient.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return trace.Wrap(err)
		}

		roleBindings, err := kubeClient.RbacV1().RoleBindings("").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return trace.Wrap(err)
		}

		for _, provision := range kubeProvisions {
			provisionClusterRoles, err := kubeProvisionToKubeClusterRoles(provision)
			if err != nil {
				return trace.Wrap(err)
			}

			for _, pcr := range provisionClusterRoles {
				foundRole := findClusterRole(clusterRoles.Items, pcr.Name)

				// Create new cluster role.
				if foundRole == nil {
					s.log.Debugf("Provisioning is creating cluster role %q from kube provision %q.", pcr.Name, provision.Metadata.Name)
					role, err := kubeClient.RbacV1().ClusterRoles().Create(ctx, &pcr, metav1.CreateOptions{})
					if err != nil {
						return trace.Wrap(err)
					}
					_ = role
				} else { // Update existing role
					foundRole.Rules = pcr.Rules

					s.log.Debugf("Provisioning is updating cluster role %q from kube provision %q.", pcr.Name, provision.Metadata.Name)
					role, err := kubeClient.RbacV1().ClusterRoles().Update(ctx, foundRole, metav1.UpdateOptions{})
					if err != nil {
						return trace.Wrap(err)
					}
					_ = role
				}

			}
		}

		for _, teleportRole := range teleportRoles {
			curRole, ok := teleportRole.(*types.RoleV6)
			if !ok {
				continue
			}

			if !strings.HasPrefix(teleportRole.GetName(), "kubepermissions") {
				continue
			}

			newRole := teleportRoleToKubeClusterRole(*curRole)
			newRole.Name = fmt.Sprintf("teleport_%s", teleportRole.GetName())
			foundClusterRole := findClusterRole(clusterRoles.Items, newRole.Name)
			if foundClusterRole == nil {
				s.log.Debugf("Provisioning is creating cluster role %q from teleport role %q.", newRole.Name, teleportRole.GetName())
				role, err := kubeClient.RbacV1().ClusterRoles().Create(ctx, &newRole, metav1.CreateOptions{})
				if err != nil {
					return trace.Wrap(err)
				}
				_ = role

				s.log.Debugf("Provisioning is creating cluster role binding %q for teleport role %q.", newRole.Name, teleportRole.GetName())
				binding := getClusterRoleBindingForClusterRole(newRole)
				newBinding, err := kubeClient.RbacV1().ClusterRoleBindings().Create(ctx, &binding, metav1.CreateOptions{})
				if err != nil {
					return trace.Wrap(err)
				}
				_ = newBinding

			} else {
				s.log.Debugf("Provisioning is updating cluster role %q from teleport role %q.", newRole.Name, teleportRole.GetName())
				role, err := kubeClient.RbacV1().ClusterRoles().Update(ctx, foundClusterRole, metav1.UpdateOptions{})
				if err != nil {
					return trace.Wrap(err)
				}
				_ = role
			}
		}

		_, _, _, _ = clusterRoles, roles, clusterRoleBindings, roleBindings
	}

	return nil
}

func getClusterRoleBindingForClusterRole(clusterRole rbacv1.ClusterRole) rbacv1.ClusterRoleBinding {
	binding := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRole.GetName(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     clusterRole.GetName(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "Group",
				APIGroup:  rbacv1.GroupName,
				Name:      clusterRole.GetName(),
				Namespace: clusterRole.GetNamespace(),
			},
		},
	}

	return binding
}

func findClusterRole(clusterRoles []rbacv1.ClusterRole, name string) *rbacv1.ClusterRole {
	for _, clusterRole := range clusterRoles {
		if clusterRole.GetName() == name {
			return &clusterRole
		}
	}
	return nil
}

func (s *TLSServer) getAllKubeProvisions() ([]*kubeprovisionv1.KubeProvision, error) {
	var resources []*kubeprovisionv1.KubeProvision
	var nextToken string
	for {
		var page []*kubeprovisionv1.KubeProvision
		var err error
		page, nextToken, err = s.AccessPoint.ListKubeProvisions(s.closeContext, 0 /* page size */, nextToken)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		resources = append(resources, page...)

		if nextToken == "" {
			break
		}
	}
	return resources, nil
}

func (s *TLSServer) startKubeProvisionWatcher(ctx context.Context) (types.Watcher, error) {
	watcher, err := s.AccessPoint.NewWatcher(ctx, types.Watch{
		Name: "kube-provision-watcher",
		Kinds: []types.WatchKind{
			{Kind: types.KindKubeProvision},
			{Kind: types.KindRole},
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	go func() {
		defer watcher.Close()

		for {
			select {
			case event := <-watcher.Events():
				s.log.Debug("DBGG. Got an event: %s", event.String())
				go func() {
					s.reconcileKubeProvisionsCh <- struct{}{}
				}()
			case <-ctx.Done():
				s.log.Debug("kube_provisions resource watcher done.")
				return
			}
		}
	}()

	return watcher, nil
}

// startKubeClusterResourceWatcher starts watching changes to Kube Clusters resources and
// registers/unregisters the proxied Kube Cluster accordingly.
func (s *TLSServer) startKubeClusterResourceWatcher(ctx context.Context) (*services.KubeClusterWatcher, error) {
	if len(s.ResourceMatchers) == 0 || s.KubeServiceType != KubeService {
		s.log.Debug("Not initializing Kube Cluster resource watcher.")
		return nil, nil
	}
	s.log.Debug("Initializing Kube Cluster resource watcher.")
	watcher, err := services.NewKubeClusterWatcher(ctx, services.KubeClusterWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: s.Component,
			Log:       s.log,
			Client:    s.AccessPoint,
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	go func() {
		defer watcher.Close()
		for {
			select {
			case clusters := <-watcher.KubeClustersC:
				s.monitoredKubeClusters.setResources(clusters)
				select {
				case s.reconcileCh <- struct{}{}:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				s.log.Debug("Kube Cluster resource watcher done.")
				return
			}
		}
	}()
	return watcher, nil
}

func (s *TLSServer) getResources() map[string]types.KubeCluster {
	return utils.FromSlice(s.fwd.kubeClusters(), types.KubeCluster.GetName)
}

func (s *TLSServer) onCreate(ctx context.Context, cluster types.KubeCluster) error {
	return s.registerKubeCluster(ctx, cluster)
}

func (s *TLSServer) onUpdate(ctx context.Context, cluster, _ types.KubeCluster) error {
	return s.updateKubeCluster(ctx, cluster)
}

func (s *TLSServer) onDelete(ctx context.Context, cluster types.KubeCluster) error {
	return s.unregisterKubeCluster(ctx, cluster.GetName())
}

func (s *TLSServer) matcher(cluster types.KubeCluster) bool {
	return services.MatchResourceLabels(s.ResourceMatchers, cluster.GetAllLabels())
}

// monitoredKubeClusters is a collection of clusters from different sources
// like configuration file and dynamic resources.
//
// It's updated by respective watchers and is used for reconciling with the
// currently proxied clusters.
type monitoredKubeClusters struct {
	// static are clusters from the agent's YAML configuration.
	static types.KubeClusters
	// resources are clusters created via CLI or API.
	resources types.KubeClusters
	// mu protects access to the fields.
	mu sync.Mutex
}

func (m *monitoredKubeClusters) setResources(clusters types.KubeClusters) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resources = clusters
}

func (m *monitoredKubeClusters) get() map[string]types.KubeCluster {
	m.mu.Lock()
	defer m.mu.Unlock()
	return utils.FromSlice(append(m.static, m.resources...), types.KubeCluster.GetName)
}

func (s *TLSServer) buildClusterDetailsConfigForCluster(cluster types.KubeCluster) clusterDetailsConfig {
	return clusterDetailsConfig{
		cloudClients:     s.CloudClients,
		cluster:          cluster,
		log:              s.log,
		checker:          s.CheckImpersonationPermissions,
		resourceMatchers: s.ResourceMatchers,
		clock:            s.Clock,
		component:        s.KubeServiceType,
	}
}

func (s *TLSServer) registerKubeCluster(ctx context.Context, cluster types.KubeCluster) error {
	clusterDetails, err := newClusterDetails(
		ctx,
		s.buildClusterDetailsConfigForCluster(cluster),
	)
	if err != nil {
		return trace.Wrap(err)
	}
	s.fwd.upsertKubeDetails(cluster.GetName(), clusterDetails)
	return trace.Wrap(s.startHeartbeat(ctx, cluster.GetName()))
}

func (s *TLSServer) updateKubeCluster(ctx context.Context, cluster types.KubeCluster) error {
	clusterDetails, err := newClusterDetails(
		ctx,
		s.buildClusterDetailsConfigForCluster(cluster),
	)
	if err != nil {
		return trace.Wrap(err)
	}
	s.fwd.upsertKubeDetails(cluster.GetName(), clusterDetails)
	return nil
}

// unregisterKubeCluster unregisters the proxied Kube Cluster from the agent.
// This function is called when the dynamic cluster is deleted/no longer match
// the agent's resource matcher or when the agent is shutting down.
func (s *TLSServer) unregisterKubeCluster(ctx context.Context, name string) error {
	var errs []error

	errs = append(errs, s.stopHeartbeat(name))
	s.fwd.removeKubeDetails(name)

	// A child process can be forked to upgrade the Teleport binary. The child
	// will take over the heartbeats so do NOT delete them in that case.
	// When unregistering a dynamic cluster, the context is empty and the
	// decision will be to delete the kubernetes server.
	if services.ShouldDeleteServerHeartbeatsOnShutdown(ctx) {
		errs = append(errs, s.deleteKubernetesServer(ctx, name))
	}

	// close active sessions before returning.
	s.fwd.mu.Lock()
	sessions := maps.Values(s.fwd.sessions)
	s.fwd.mu.Unlock()
	// close active sessions
	for _, sess := range sessions {
		if sess.ctx.kubeClusterName == name {
			// TODO(tigrato): check if we should send errors to each client
			errs = append(errs, sess.Close())
		}
	}

	return trace.NewAggregate(errs...)
}

// deleteKubernetesServer deletes kubernetes server for the specified cluster.
func (s *TLSServer) deleteKubernetesServer(ctx context.Context, name string) error {
	err := s.AuthClient.DeleteKubernetesServer(ctx, s.HostID, name)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	return nil
}
