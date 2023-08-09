/*
Copyright 2019-2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import { useEffect } from 'react';

import { Attempt } from 'shared/hooks/useAttemptNext';
import { LoginItem } from 'shared/components/MenuLogin';

import Ctx from 'teleport/teleportContext';
import useStickyClusterId from 'teleport/useStickyClusterId';
import cfg from 'teleport/config';
import { useUrlFiltering } from 'teleport/components/hooks';
import { useInfiniteScroll } from 'teleport/components/hooks/useInfiniteScroll';
import { openNewTab } from 'teleport/lib/util';
import { AgentResponse, UnifiedResource } from 'teleport/services/agents';
import { UrlFilteringState } from 'teleport/components/hooks/useUrlFiltering/useUrlFiltering';
import { Node } from 'teleport/services/nodes';
import { AuthType } from 'teleport/services/user';
import { Desktop } from 'teleport/services/desktops';

export interface ResourcesState {
  clusterId: string;
  fetchedData: AgentResponse<UnifiedResource>;
  fetchMore: () => void;
  getNodeLoginOptions: (serverId: string) => LoginItem[];
  getWindowsLoginOptions: (desktop: Desktop) => LoginItem[];
  username: string;
  authType: AuthType;
  startSshSession: (login: string, serverId: string) => void;
  startRemoteDesktopSession: (username: string, desktopName: string) => void;
  attempt: Attempt;
  accessRequestId: string;
  filtering: UrlFilteringState;
  canCreate: boolean;
  isLeafCluster: boolean;
}

/**
 * Retrieves a batch of unified resources from the server, taking into
 * consideration URL filter. Use the returned `fetchInitial` function to fetch
 * the initial batch, and `fetchMore` to support infinite scrolling.
 */
export function useResources(ctx: Ctx): ResourcesState {
  const { clusterId, isLeafCluster } = useStickyClusterId();
  const username = ctx.storeUser.state.username;
  const canCreate = ctx.storeUser.getTokenAccess().create;
  const authType = ctx.storeUser.state.authType;
  const accessRequestId = ctx.storeUser.getAccessRequestId();

  const filtering = useUrlFiltering({
    fieldName: 'name',
    dir: 'ASC',
  });
  const { params, search } = filtering;

  const { fetchInitial, fetchedData, attempt, fetchMore } = useInfiniteScroll({
    fetchFunc: ctx.resourceService.fetchUnifiedResources,
    clusterId,
    params,
  });

  useEffect(() => {
    fetchInitial();
  }, [clusterId, search]);

  const getWindowsLoginOptions = ({ name, logins }: Desktop) =>
    makeDesktopLoginOptions(clusterId, name, logins);

  const startRemoteDesktopSession = (username: string, desktopName: string) => {
    const url = cfg.getDesktopRoute({
      clusterId,
      desktopName,
      username,
    });

    openNewTab(url);
  };

  function getNodeLoginOptions(serverId: string) {
    const node = filterNodes(fetchedData.agents).find(
      node => node.id == serverId
    );
    return makeOptions(clusterId, node);
  }

  const startSshSession = (login: string, serverId: string) => {
    const url = cfg.getSshConnectRoute({
      clusterId,
      serverId,
      login,
    });

    openNewTab(url);
  };

  return {
    clusterId,
    fetchedData,
    canCreate,
    isLeafCluster,
    fetchMore,
    username,
    authType,
    accessRequestId,
    getNodeLoginOptions,
    getWindowsLoginOptions,
    startSshSession,
    startRemoteDesktopSession,
    attempt,
    filtering,
  };
}

function filterNodes(resources: UnifiedResource[]): Node[] {
  return resources.filter(resource => resource.kind === 'node') as Node[];
}

function makeOptions(clusterId: string, node: Node | undefined) {
  const nodeLogins = node?.sshLogins || [];
  const logins = sortLogins(nodeLogins);

  return logins.map(login => {
    const url = cfg.getSshConnectRoute({
      clusterId,
      serverId: node?.id || '',
      login,
    });

    return {
      login,
      url,
    };
  });
}

function makeDesktopLoginOptions(
  clusterId: string,
  desktopName = '',
  logins = [] as string[]
): LoginItem[] {
  return logins.map(username => {
    const url = cfg.getDesktopRoute({
      clusterId,
      desktopName,
      username,
    });

    return {
      login: username,
      url,
    };
  });
}

// sort logins by making 'root' as the first in the list
export const sortLogins = (logins: string[]) => {
  const noRoot = logins.filter(l => l !== 'root').sort();
  if (noRoot.length === logins.length) {
    return logins;
  }
  return ['root', ...noRoot];
};
